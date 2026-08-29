// Package carrier provides GID/SPN-based carrier profile lookup.
//
// Matching strategy (priority high → low):
//  0. User override (DB-registered config, highest priority)
//  1. GID1/GID2 match → carrier_index subs → brandToFilename → profile
//  2. SPN match → carrier_index subs[].names → brandToFilename → profile
//  3. Primary operator brand → brandToFilename → profile
//  4. generic default (3GPP standard)

package carrier

import (
	"embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed profiles/*.json
var profileFS embed.FS

// CarrierIndexProvider supplies carrier index data from an external source
// (e.g. vohive-next's DB carrier_index table). vowifi-core cannot import
// vohive-next/internal/db, so this interface is injected at startup.
type CarrierIndexProvider interface {
	// GetCarrierIndexRawJSON returns the raw JSON string for a PLMN key
	// (e.g. "234-10"). Returns empty string if not found.
	GetCarrierIndexRawJSON(plmnKey string) string
}

// carrierIndexCountry holds the country info from all.json.
type carrierIndexCountry struct {
	Name   string `json:"name"`
	ISO    string `json:"iso"`
	Code   string `json:"code"`
	Region string `json:"region"`
}

// carrierIndexSub represents a sub-brand entry in the carrier index.
type carrierIndexSub struct {
	Brand        string   `json:"brand"`
	Names        []string `json:"names"`
	GID1         string   `json:"gid1"`
	GID2         string   `json:"gid2"`
	ProfileNames []string `json:"profile_names"`
}

// carrierIndexOperator represents an operator entry in the carrier index.
type carrierIndexOperator struct {
	Brand    string             `json:"brand"`
	Operator string             `json:"operator"`
	Subs     []carrierIndexSub `json:"subs"`
}

// carrierIndexEntry represents the top-level structure stored in raw_json.
type carrierIndexEntry struct {
	MCC       string                 `json:"mcc"`
	MNC       string                 `json:"mnc"`
	Country   carrierIndexCountry    `json:"country"`
	Operators []carrierIndexOperator `json:"operators"`
}

var (
	profileCache sync.Map // filename → *CarrierProfile

	carrierIndexProvider CarrierIndexProvider
	providerMu           sync.RWMutex
)

// SetCarrierIndexProvider injects the DB query capability.
// Must be called once at startup before any LookupWithIdentity call.
func SetCarrierIndexProvider(p CarrierIndexProvider) {
	providerMu.Lock()
	carrierIndexProvider = p
	providerMu.Unlock()
}

// LookupWithIdentity finds the carrier profile for the given PLMN + GID identity.
//
// Matching strategy (priority high → low):
//  0. User override (DB-registered, highest priority)
//  1. GID1/GID2 match → carrier_index subs → brandToFilename → profile
//  2. SPN match → carrier_index subs[].names → brandToFilename → profile
//  3. Primary operator brand → brandToFilename → profile
//  4. generic default (3GPP standard)
//
// PLMN is always available from the SIM. GID1/GID2 may be empty for some USIMs.
// When GID matching fails, we fall back to the PLMN's primary operator profile
// (e.g. Vodafone UK for PLMN 234-15), not generic.
func LookupWithIdentity(mcc, mnc, gid1, gid2, spn string) (*CarrierProfile, error) {
	plmnKey := plmnKey(mcc, mnc)

	// 0. User override (highest priority — user-defined config from DB)
	if p, err := LookupWithSPN(mcc, mnc, spn); err == nil && p != nil {
		return p, nil
	}

	// Load carrier index entry from DB
	ciEntry := loadCarrierIndexEntry(plmnKey)
	if ciEntry == nil {
		// No carrier index data — fall back to generic
		p, _ := Generic()
		return p, nil
	}

	iso := ciEntry.Country.ISO

	// 1. GID1/GID2 match against subs
	if gid1 != "" || gid2 != "" {
		if filename := matchByGID(ciEntry, gid1, gid2, iso); filename != "" {
			if p := loadProfile(filename); p != nil {
				return p, nil
			}
		}
	}

	// 2. SPN match against subs[].names
	if spn != "" {
		if filename := matchBySPN(ciEntry, spn, iso); filename != "" {
			if p := loadProfile(filename); p != nil {
				return p, nil
			}
		}
	}

	// 3. Primary operator brand → filename
	if len(ciEntry.Operators) > 0 {
		primaryBrand := ciEntry.Operators[0].Brand
		if filename := brandToFilename(primaryBrand, iso); filename != "" {
			if p := loadProfile(filename); p != nil {
				return p, nil
			}
		}

		// Try all operators as fallback
		for _, op := range ciEntry.Operators {
			if filename := brandToFilename(op.Brand, iso); filename != "" {
				if p := loadProfile(filename); p != nil {
					return p, nil
				}
			}
		}
	}

	// 4. Final fallback: generic default
	p, _ := Generic()
	return p, nil
}

// matchByGID matches GID1/GID2 against carrier index subs.
// When a sub's GID matches, generates the profile filename from sub.Brand + iso.
func matchByGID(entry *carrierIndexEntry, gid1, gid2, iso string) string {
	if entry == nil {
		return ""
	}

	gid1 = strings.ToLower(strings.TrimSpace(gid1))
	gid2 = strings.ToLower(strings.TrimSpace(gid2))

	for _, op := range entry.Operators {
		for _, sub := range op.Subs {
			subGID1 := strings.ToLower(sub.GID1)
			subGID2 := strings.ToLower(sub.GID2)

			if gidPrefixMatch(gid1, subGID1) || gidPrefixMatch(gid2, subGID2) {
				if filename := brandToFilename(sub.Brand, iso); filename != "" {
					return filename
				}
			}
		}
	}
	return ""
}

// matchBySPN matches the SIM's SPN against carrier index subs[].names.
// When a name matches, generates the profile filename from sub.Brand + iso.
func matchBySPN(entry *carrierIndexEntry, spn, iso string) string {
	if entry == nil {
		return ""
	}

	spn = strings.ToLower(strings.TrimSpace(spn))
	if spn == "" {
		return ""
	}

	for _, op := range entry.Operators {
		for _, sub := range op.Subs {
			for _, name := range sub.Names {
				if strings.EqualFold(spn, name) {
					if filename := brandToFilename(sub.Brand, iso); filename != "" {
						return filename
					}
				}
			}
			// Also check sub.Brand directly against SPN
			if sub.Brand != "" && strings.EqualFold(spn, sub.Brand) {
				if filename := brandToFilename(sub.Brand, iso); filename != "" {
					return filename
				}
			}
		}
	}
	return ""
}

// loadCarrierIndexEntry queries the DB and parses the carrier index raw_json
// for the given PLMN key. Returns nil if not available.
func loadCarrierIndexEntry(plmnKey string) *carrierIndexEntry {
	providerMu.RLock()
	p := carrierIndexProvider
	providerMu.RUnlock()
	if p == nil {
		return nil
	}

	rawJSON := p.GetCarrierIndexRawJSON(plmnKey)
	if rawJSON == "" {
		return nil
	}

	var entry carrierIndexEntry
	if json.Unmarshal([]byte(rawJSON), &entry) != nil {
		return nil
	}
	return &entry
}

// gidPrefixMatch checks if two GID hex strings match via bidirectional prefix.
// Either side can be a prefix of the other (SIM GID may be longer or shorter
// than the index entry depending on padding).
func gidPrefixMatch(simGID, mapGID string) bool {
	simGID = strings.ToLower(simGID)
	mapGID = strings.ToLower(mapGID)
	if simGID == "" || mapGID == "" {
		return false
	}
	return strings.HasPrefix(simGID, mapGID) || strings.HasPrefix(mapGID, simGID)
}

// isoAliases maps standard ISO codes to the suffix used in profile filenames.
// For example, GB (United Kingdom) is stored as ISO "GB" but profile files
// use "uk" as the suffix (e.g. vodafone_uk.json, ee_uk.json).
var isoAliases = map[string]string{
	"gb": "uk",
}

// brandToFilename generates the expected profile filename from a brand name
// and ISO country code.
//
// Strategy (all case-insensitive):
//  1. Direct: brand_lower + _ + iso_lower (with ISO alias if applicable)
//  2. Strip country suffix from brand: "Vodafone UK" → "vodafone" + _ + "uk"
//  3. Try original brand without any country suffix (for MVNOs without country)
//
// Returns empty string if no matching file exists in profiles/.
func brandToFilename(brand, iso string) string {
	brand = strings.TrimSpace(brand)
	if brand == "" {
		return ""
	}

	isoLower := strings.ToLower(iso)
	// Apply ISO alias (e.g. gb → uk)
	if alias, ok := isoAliases[isoLower]; ok {
		isoLower = alias
	}

	// Strategy 1: direct brand + _ + iso
	candidate := normalizeBrand(brand) + "_" + isoLower
	if profileExists(candidate) {
		return candidate
	}

	// Strategy 2: strip country suffix from brand, then add iso
	stripped := stripCountrySuffix(brand)
	if stripped != "" && stripped != brand {
		candidate2 := normalizeBrand(stripped) + "_" + isoLower
		if profileExists(candidate2) {
			return candidate2
		}
	}

	// Strategy 3: brand only, no country suffix (for MVNOs like "Airalo")
	candidate3 := normalizeBrand(brand)
	if profileExists(candidate3) {
		return candidate3
	}

	return ""
}

// stripCountrySuffix removes a trailing country name/code from a brand string.
// e.g. "Vodafone UK" → "Vodafone", "Orange Belgium" → "Orange".
func stripCountrySuffix(brand string) string {
	lower := strings.ToLower(brand)
	suffixes := []string{
		" uk", " us", " fr", " de", " it", " es",
		" nl", " be", " gr", " au", " jp", " ca",
		" ireland", " germany", " france", " italy",
		" spain", " netherlands", " belgium", " greece",
		" australia", " japan", " canada",
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(lower, suffix) {
			return strings.TrimSpace(brand[:len(brand)-len(suffix)])
		}
	}
	return ""
}

// normalizeBrand converts a brand name to a normalized filename component.
// e.g. "Vodafone UK" → "vodafone_uk", "O2" → "o2", "T-Mobile" → "t_mobile".
func normalizeBrand(brand string) string {
	name := strings.ToLower(brand)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")
	// Remove any non-alphanumeric chars (keep a-z, 0-9, _)
	var b strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// profileExists checks if a profile file exists in the embedded filesystem.
func profileExists(filename string) bool {
	if filename == "" {
		return false
	}
	data, err := profileFS.ReadFile("profiles/" + filename + ".json")
	return err == nil && len(data) > 0
}

// loadProfile loads a carrier profile JSON from embedded filesystem.
// Results are cached in a sync.Map.
func loadProfile(filename string) *CarrierProfile {
	if cached, ok := profileCache.Load(filename); ok {
		if p, ok := cached.(*CarrierProfile); ok {
			return p
		}
	}

	data, err := profileFS.ReadFile("profiles/" + filename + ".json")
	if err != nil {
		return nil
	}

	var p CarrierProfile
	if json.Unmarshal(data, &p) != nil {
		return nil
	}

	// System templates always have template_level=default
	if p.TemplateLevel == "" {
		p.TemplateLevel = "default"
	}

	profileCache.Store(filename, &p)
	return &p
}

// PlmnKey builds a normalized PLMN key (e.g. "234-10").
// MNC leading zeros are stripped so that "15" and "015" both produce "234-15".
// This is the single source of truth for PLMN key generation across the codebase.
func PlmnKey(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	// MNC 统一补零到 3 位（3GPP 标准格式）
	if len(mnc) < 3 {
		mnc = strings.Repeat("0", 3-len(mnc)) + mnc
	}
	return mcc + "-" + mnc
}

// plmnKey is retained as an alias for internal use to minimize diff noise.
// New code should use PlmnKey directly.
func plmnKey(mcc, mnc string) string {
	return PlmnKey(mcc, mnc)
}
