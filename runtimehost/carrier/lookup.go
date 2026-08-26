// Package carrier provides GID-based carrier profile lookup.
//
// Matching strategy (priority high → low):
//  0. User override (DB-registered config, highest priority)
//  1. GID1/GID2 direct map lookup → exact filename (no name fuzzy matching)
//  2. GID prefix match → carrier_index subs (DB)
//  3. GID miss → primary operator brand → profile file
//  4. Candidate files first match (primary operator for this PLMN)
//  5. generic default

package carrier

import (
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

//go:embed profiles/*.json
var profileFS embed.FS

//go:embed embed/plmn_profile_map.json
var plmnProfileMapRaw []byte

// CarrierIndexProvider supplies carrier index data from an external source
// (e.g. vohive-next's DB carrier_index table). vowifi-core cannot import
// vohive-next/internal/db, so this interface is injected at startup.
type CarrierIndexProvider interface {
	// GetCarrierIndexRawJSON returns the raw JSON string for a PLMN key
	// (e.g. "234-10"). Returns empty string if not found.
	GetCarrierIndexRawJSON(plmnKey string) string
}

// plmnProfileEntry is the enhanced map entry for each PLMN key.
type plmnProfileEntry struct {
	Profiles []string            `json:"profiles"` // candidate profile filenames
	GID1Map  map[string]string   `json:"gid1_map"` // GID1 hex → filename
	GID2Map  map[string]string   `json:"gid2_map"` // GID2 hex → filename
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
	MCC       string               `json:"mcc"`
	MNC       string               `json:"mnc"`
	Operators []carrierIndexOperator `json:"operators"`
}

var (
	mapOnce  sync.Once
	mapCache map[string]plmnProfileEntry
	mapErr   error

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

// loadMap parses plmn_profile_map.json once at first use.
func loadMap() {
	mapOnce.Do(func() {
		if err := json.Unmarshal(plmnProfileMapRaw, &mapCache); err != nil {
			mapErr = fmt.Errorf("carrier: parse plmn_profile_map: %w", err)
			return
		}
	})
}

// LookupWithIdentity finds the carrier profile for the given PLMN + GID identity.
//
// Matching strategy (priority high → low):
//  0. User override (DB-registered, highest priority)
//  1. GID1/GID2 direct map lookup → exact filename (no fuzzy name matching)
//  2. GID prefix match → carrier_index subs (DB)
//  3. GID miss → primary operator brand → profile (from carrier_index DB)
//  4. Candidate files first match (primary operator for this PLMN)
//  5. generic default
//
// PLMN is always available from the SIM. GID1/GID2 may be empty for some USIMs.
// When GID matching fails, we fall back to the PLMN's primary operator profile
// (e.g. Vodafone UK for PLMN 234-15), not generic.
func LookupWithIdentity(mcc, mnc, gid1, gid2, spn string) (*CarrierProfile, error) {
	loadMap()
	if mapErr != nil {
		return nil, mapErr
	}

	plmnKey := plmnKey(mcc, mnc)
	entry, _ := mapCache[plmnKey]
	candidateFiles := entry.Profiles

	slog.Info("🔍 [carrier] LookupWithIdentity 开始查找",
		"plmn", plmnKey,
		"gid1", gid1, "gid2", gid2, "spn", spn,
		"candidates", candidateFiles)

	// 0. User override (highest priority — user-defined config from DB)
	if p, err := LookupWithSPN(mcc, mnc, spn); err == nil && p != nil {
		slog.Info("✅ [carrier] 匹配到用户覆盖配置", "plmn", plmnKey, "step", "0_user_override", "profile_id", p.ID)
		return p, nil
	}

	// 1. GID direct map lookup (exact match, no fuzzy name matching)
	if gid1 != "" || gid2 != "" {
		if matched := lookupByGIDMap(gid1, gid2, entry); matched != "" {
			if p := loadProfile(matched); p != nil {
				slog.Info("✅ [carrier] 匹配到 GID 直接映射", "plmn", plmnKey, "step", "1_gid_map", "profile_file", matched, "profile_id", p.ID)
				return p, nil
			}
		}
	}

	// 2. GID prefix match against carrier_index subs (fallback for GIDs
	//    not in plmn_profile_map but in DB carrier_index)
	ciEntry := loadCarrierIndexEntry(plmnKey)
	if gid1 != "" || gid2 != "" {
		if matched := matchByGIDPrefix(ciEntry, gid1, gid2, candidateFiles); matched != "" {
			if p := loadProfile(matched); p != nil {
				slog.Info("✅ [carrier] 匹配到 GID 前缀匹配", "plmn", plmnKey, "step", "2_gid_prefix", "profile_file", matched, "profile_id", p.ID)
				return p, nil
			}
		}
	}

	// 3. GID miss → primary operator brand match
	if matched := matchPrimaryOperator(ciEntry, candidateFiles); matched != "" {
		if p := loadProfile(matched); p != nil {
			slog.Info("✅ [carrier] 匹配到主运营商品牌", "plmn", plmnKey, "step", "3_primary_operator", "profile_file", matched, "profile_id", p.ID)
			return p, nil
		}
	}

	// 4. Candidate files first match (when DB is empty but map has entries)
	if len(candidateFiles) > 0 {
		if p := loadProfile(candidateFiles[0]); p != nil {
			slog.Info("✅ [carrier] 匹配到候选文件第一个", "plmn", plmnKey, "step", "4_candidate_first", "profile_file", candidateFiles[0], "profile_id", p.ID)
			return p, nil
		}
	}

	// 5. Final fallback: generic default
	p, _ := Generic()
	slog.Warn("⚠️ [carrier] 所有匹配失败，使用 generic 默认配置", "plmn", plmnKey, "step", "5_generic_fallback", "profile_id", p.ID)
	return p, nil
}

// lookupByGIDMap does a direct lookup in plmn_profile_map's gid1_map/gid2_map.
// GID values are hex strings, compared case-insensitively with prefix matching
// (bidirectional: SIM GID may be longer/shorter than map entry due to padding).
func lookupByGIDMap(gid1, gid2 string, entry plmnProfileEntry) string {
	gid1 = strings.ToLower(strings.TrimSpace(gid1))
	gid2 = strings.ToLower(strings.TrimSpace(gid2))

	// Check GID1 map
	if gid1 != "" {
		for mapGID, filename := range entry.GID1Map {
			if gidPrefixMatch(gid1, mapGID) {
				return filename
			}
		}
	}

	// Check GID2 map
	if gid2 != "" {
		for mapGID, filename := range entry.GID2Map {
			if gidPrefixMatch(gid2, mapGID) {
				return filename
			}
		}
	}

	return ""
}

// matchByGIDPrefix matches GID1/GID2 against carrier index subs.
// This is a fallback for GIDs not in plmn_profile_map but in DB.
func matchByGIDPrefix(entry *carrierIndexEntry, gid1, gid2 string, candidateFiles []string) string {
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
				if matched := findProfileByBrand(sub.Brand, sub.Names, candidateFiles); matched != "" {
					return matched
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

// matchPrimaryOperator matches the primary operator's brand to a profile file.
// The first operator in the carrier index is the PLMN's primary operator.
func matchPrimaryOperator(entry *carrierIndexEntry, candidateFiles []string) string {
	if entry == nil || len(entry.Operators) == 0 {
		return ""
	}

	// First operator = primary operator for this PLMN
	primaryBrand := entry.Operators[0].Brand
	if matched := findProfileByBrand(primaryBrand, nil, candidateFiles); matched != "" {
		return matched
	}

	// Try all operators as fallback
	for _, op := range entry.Operators {
		if matched := findProfileByBrand(op.Brand, nil, candidateFiles); matched != "" {
			return matched
		}
	}
	return ""
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

// findProfileByBrand tries to find a carrier-profile JSON file matching
// the given brand name from the candidate files list.
// Used as a last resort fallback (GID direct map is primary).
//
// Matching (case-insensitive, dashes treated as underscores):
//  1. Exact match (brand normalized: lowercase, spaces/dashes→underscores)
//  2. Brand is a substring of filename
//  3. Any name in names[] matches
func findProfileByBrand(brand string, names []string, candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	// Try brand first, then names
	searchTerms := []string{brand}
	searchTerms = append(searchTerms, names...)

	for _, term := range searchTerms {
		term = strings.ToLower(strings.TrimSpace(term))
		if term == "" {
			continue
		}
		norm := strings.NewReplacer(" ", "_", "-", "_").Replace(term)

		// 1. Exact match
		for _, c := range candidates {
			if strings.ToLower(c) == norm {
				return c
			}
		}

		// 2. Term is substring of candidate
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(c), norm) {
				return c
			}
		}

		// 3. Candidate is substring of term (min 3 chars)
		for _, c := range candidates {
			cl := strings.ToLower(c)
			if len(cl) >= 3 && strings.Contains(norm, cl) {
				return c
			}
		}
	}

	return ""
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

	profileCache.Store(filename, &p)
	return &p
}

// plmnKey builds a normalized PLMN key (e.g. "234-10").
func plmnKey(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	mncTrimmed := strings.TrimLeft(mnc, "0")
	if mncTrimmed == "" && mnc != "" {
		mncTrimmed = "0"
	}
	return mcc + "-" + mncTrimmed
}
