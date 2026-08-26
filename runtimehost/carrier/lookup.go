// Package carrier provides GID-based carrier profile lookup.
//
// This file implements the GID matching logic for carrier profiles:
//  1. Query CarrierIndexProvider for the PLMN's raw operator data
//  2. Parse operators[].subs[] and match GID1/GID2 (prefix match)
//  3. Match sub.brand to a carrier-profile JSON filename
//  4. Load the JSON file from embedded carrier-profiles
//  5. Fall back: operator.brand → PLMN key (legacy profiles) → generic

package carrier

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/voorz/vowifi-core/profiles"
)

//go:embed profiles/*.json
var profileFS embed.FS

//go:embed plmn_profile_map.json
var plmnProfileMapRaw []byte

// CarrierIndexProvider supplies carrier index data from an external source
// (e.g. vohive-next's DB carrier_index table). vowifi-core cannot import
// vohive-next/internal/db, so this interface is injected at startup.
type CarrierIndexProvider interface {
	// GetCarrierIndexRawJSON returns the raw JSON string for a PLMN key
	// (e.g. "234-10"). Returns empty string if not found.
	GetCarrierIndexRawJSON(plmnKey string) string
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
	MCC        string                 `json:"mcc"`
	MNC        string                 `json:"mnc"`
	Operators  []carrierIndexOperator `json:"operators"`
}

var (
	mapOnce  sync.Once
	mapCache map[string][]string
	mapErr  error

	profileCache sync.Map{} // filename → *profiles.CarrierProfile

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
// Matching priority:
//  1. GID1/GID2 prefix match against carrier_index subs → sub.brand → profile file
//  2. operator.brand → profile file
//  3. Legacy embed profiles (PLMN key lookup via profiles.LookupWithSPN)
//  4. generic.json
//
// Returns nil if no profile found (caller should use profiles.Generic).
func LookupWithIdentity(mcc, mnc, gid1, gid2, spn string) (*profiles.CarrierProfile, error) {
	loadMap()
	if mapErr != nil {
		return nil, mapErr
	}

	plmnKey := plmnKey(mcc, mnc)
	candidateFiles := mapCache[plmnKey]

	// 1. Try GID match from carrier index
	if matched := matchByGID(plmnKey, gid1, gid2, candidateFiles); matched != "" {
		if p := loadProfile(matched); p != nil {
			return p, nil
		}
	}

	// 2. Try operator brand match
	if matched := matchByOperatorBrand(plmnKey, candidateFiles); matched != "" {
		if p := loadProfile(matched); p != nil {
			return p, nil
		}
	}

	// 3. Fall back to legacy embed profiles
	if p, err := profiles.LookupWithSPN(mcc, mnc, spn); err == nil && p != nil {
		return p, nil
	}

	// 4. Final fallback: generic
	return profiles.Generic()
}

// matchByGID queries carrier index and matches GID1/GID2 against subs.
func matchByGID(plmnKey, gid1, gid2 string, candidateFiles []string) string {
	if gid1 == "" && gid2 == "" {
		return ""
	}

	providerMu.RLock()
	p := carrierIndexProvider
	providerMu.RUnlock()
	if p == nil {
		return ""
	}

	rawJSON := p.GetCarrierIndexRawJSON(plmnKey)
	if rawJSON == "" {
		return ""
	}

	var entry carrierIndexEntry
	if json.Unmarshal([]byte(rawJSON), &entry) != nil {
		return ""
	}

	for _, op := range entry.Operators {
		for _, sub := range op.Subs {
			if gidMatches(gid1, gid2, sub.GID1, sub.GID2) {
				if matched := findProfileByBrand(sub.Brand, candidateFiles); matched != "" {
					return matched
				}
			}
		}
	}
	return ""
}

// matchByOperatorBrand tries to match operator brands to candidate files.
func matchByOperatorBrand(plmnKey string, candidateFiles []string) string {
	providerMu.RLock()
	p := carrierIndexProvider
	providerMu.RUnlock()
	if p == nil {
		return ""
	}

	rawJSON := p.GetCarrierIndexRawJSON(plmnKey)
	if rawJSON == "" {
		return ""
	}

	var entry carrierIndexEntry
	if json.Unmarshal([]byte(rawJSON), &entry) != nil || len(entry.Operators) == 0 {
		return ""
	}

	for _, op := range entry.Operators {
		if matched := findProfileByBrand(op.Brand, candidateFiles); matched != "" {
			return matched
		}
	}
	return ""
}

// gidMatches checks if SIM GID1/GID2 match the sub's GID1/GID2 via prefix match.
// GID values are hex strings. Match is bidirectional prefix (either side can be
// the prefix of the other, since SIM GID may be longer or shorter than the
// index entry depending on padding).
func gidMatches(simGID1, simGID2, subGID1, subGID2 string) bool {
	if subGID1 != "" && simGID1 != "" {
		if strings.HasPrefix(simGID1, subGID1) || strings.HasPrefix(subGID1, simGID1) {
			return true
		}
	}
	if subGID2 != "" && simGID2 != "" {
		if strings.HasPrefix(simGID2, subGID2) || strings.HasPrefix(subGID2, simGID2) {
			return true
		}
	}
	return false
}

// findProfileByBrand tries to find a carrier-profile JSON file matching
// the given brand name from the candidate files list.
//
// Matching (case-insensitive):
//  1. Exact match (brand normalized: lowercase, spaces→underscores)
//  2. Brand is a substring of filename
func findProfileByBrand(brand string, candidates []string) string {
	brand = strings.ToLower(strings.TrimSpace(brand))
	if brand == "" || len(candidates) == 0 {
		return ""
	}
	brandNorm := strings.ReplaceAll(brand, " ", "_")

	// 1. Exact match
	for _, c := range candidates {
		if strings.ToLower(c) == brandNorm {
			return c
		}
	}

	// 2. Brand substring of filename
	for _, c := range candidates {
		cl := strings.ToLower(c)
		if strings.Contains(cl, brandNorm) {
			return c
		}
	}

	return ""
}

// loadProfile loads a carrier profile JSON from embedded filesystem.
// Results are cached in a sync.Map.
func loadProfile(filename string) *profiles.CarrierProfile {
	if cached, ok := profileCache.Load(filename); ok {
		if p, ok := cached.(*profiles.CarrierProfile); ok {
			return p
		}
	}

	data, err := profileFS.ReadFile("profiles/" + filename + ".json")
	if err != nil {
		return nil
	}

	var p profiles.CarrierProfile
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
