// Package carrier resolves per-PLMN VoWiFi behavior: ePDG address overrides,
// AKA application preference, e911 entitlement availability, and policy blocks.
//
// Every PLMN works out of the box via the 3GPP TS 23.003 default (computed in
// the identity package). This package only holds the *exceptions*: operators
// whose real-world ePDG deployment deviates from the standard FQDN, or that
// need e911/policy handling. Those exceptions are loaded from an optional
// external JSON file so they can be updated without a rebuild.
package carrier

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Preset is a single PLMN override entry in the external carrier_overrides file.
type Preset struct {
	ID               string `json:"id"`
	MCC              string `json:"mcc"`
	MNC              string `json:"mnc"`
	EPDGAddr         string `json:"epdg_addr,omitempty"`
	AKAAppPreference string `json:"aka_app_preference,omitempty"` // "usim" | "isim" | "auto"
	// IMSTAC and IMSCellID are optional LTE identities used in Cellular-Network-Info
	// when live QMI cell readings are unavailable. Values may be decimal or hex in
	// JSON; giffgaff/O2 commonly use TAC 28673 and Cell ID 12345678.
	IMSTAC    uint32 `json:"ims_tac,omitempty"`
	IMSCellID uint32 `json:"ims_cell_id,omitempty"`
	// IMSCellIDMode controls utran-cell-id selection for IMS REGISTER:
	//   "" or "qmi_first" — live QMI, then carrier preset fallback
	//   "carrier_only"  — always use ims_tac/ims_cell_id preset
	//   "none"          — skip cell-id injection (REGISTER uses zero placeholder)
	IMSCellIDMode string `json:"ims_cell_id_mode,omitempty"`
	// IMSRegisterProfile selects a handset REGISTER mimic profile (e.g. "xiaomi_mi11").
	IMSRegisterProfile string `json:"ims_register_profile,omitempty"`
	// PhoneIMEI is the IMEI used to build urn:gsma:imei:... for +sip.instance spoofing.
	PhoneIMEI string `json:"phone_imei,omitempty"`
	// IMSPcscfAddr optionally overrides the IKE-discovered P-CSCF ("host:port").
	// Useful when ePDG assigns a silent node but a known-good P-CSCF responds.
	IMSPcscfAddr string `json:"ims_pcscf_addr,omitempty"`
	E911Enabled              bool   `json:"e911_enabled,omitempty"`
	E911Provider             string `json:"e911_provider,omitempty"`
	E911Websheet             string `json:"e911_websheet,omitempty"`
	E911EntitlementEndpoint  string `json:"e911_entitlement_endpoint,omitempty"`
	RFOffDelay               int    `json:"rf_off_delay,omitempty"`
	Blocked                  bool   `json:"blocked,omitempty"`
}

type EffectiveCarrierConfigInput struct {
	MCC string
	MNC string
	SPN string // SIM SPN for MVNO disambiguation (optional)
}

type EffectiveCarrierConfig struct {
	PresetID         string
	EPDGAddr         string
	AKAAppPreference string
	RFOffDelay       int
	E911             struct {
		Enabled             bool
		Provider            string
		Websheet            string
		EntitlementEndpoint string
	}
}

type LoadResult struct {
	Path    string
	Missing bool
	Count   int
}

var (
	mu      sync.RWMutex
	presets = map[string]Preset{}
)

// builtinDefaults has been removed. All carrier-specific defaults are now
// sourced from embedded JSON profiles (profiles/*.json) via lookupWithJSON().

// blockedMCCs are entire countries where VoWiFi is policy-blocked regardless
// of which network the SIM is on. Add an MCC here to block all operators
// under that country.
var blockedMCCs = map[string]bool{}


// LoadCarrierOverrides loads a JSON array of Preset from path, replacing any
// previously loaded overrides. An empty path or a nonexistent file is not an
// error: it just means no overrides are active, so every PLMN falls back to
// the 3GPP-standard default.
func LoadCarrierOverrides(path string) (*LoadResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		ClearCarrierOverrides()
		return &LoadResult{Path: path, Missing: true}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			ClearCarrierOverrides()
			return &LoadResult{Path: path, Missing: true}, nil
		}
		return &LoadResult{Path: path}, fmt.Errorf("carrier: read %s: %w", path, err)
	}

	var loaded []Preset
	if err := json.Unmarshal(data, &loaded); err != nil {
		return &LoadResult{Path: path}, fmt.Errorf("carrier: parse %s: %w", path, err)
	}

	next := make(map[string]Preset, len(loaded))
	for _, p := range loaded {
		if strings.TrimSpace(p.MCC) == "" || strings.TrimSpace(p.MNC) == "" {
			continue
		}
		next[plmnKey(p.MCC, p.MNC)] = p
	}

	mu.Lock()
	presets = next
	mu.Unlock()

	return &LoadResult{Path: path, Count: len(next)}, nil
}

func ClearCarrierOverrides() {
	mu.Lock()
	presets = map[string]Preset{}
	mu.Unlock()
}

// lookup checks loaded external overrides only. Carrier-specific defaults
// are sourced from embedded JSON profiles via lookupWithJSON().
func lookup(mcc, mnc string) (Preset, bool) {
	key := plmnKey(mcc, mnc)
	mu.RLock()
	p, ok := presets[key]
	mu.RUnlock()
	return p, ok
}

// lookupWithJSON checks the embedded JSON profiles (including user overrides)
// first, falling back to lookup() (loaded external overrides).
// This is the JSON-first path used by all L1 carrier functions.
func lookupWithJSON(mcc, mnc, spn string) (Preset, bool) {
	if p, err := LookupWithSPN(mcc, mnc, spn); err == nil && p != nil {
		return carrierProfileToPreset(p), true
	}
	return lookup(mcc, mnc)
}

// carrierProfileToPreset maps a CarrierProfile to a carrier.Preset
// so that L1 functions can consume JSON profile fields uniformly.
func carrierProfileToPreset(p *CarrierProfile) Preset {
	return Preset{
		ID:                     p.ID,
		MCC:                    p.MCC,
		MNC:                    p.MNC,
		EPDGAddr:               p.IKE.Addr,
		AKAAppPreference:       p.EAP.AppPreference,
		IMSTAC:                 uint32(p.Device.IMSTAC),
		IMSCellID:              uint32(p.Device.IMSCellID),
		IMSCellIDMode:          p.Device.IMSCellIDMode,
		IMSRegisterProfile:     p.Device.IMSRegisterProfile,
		PhoneIMEI:              p.Device.IMEI,
		IMSPcscfAddr:           p.IMS.PCSCFAddr,
		E911Enabled:            p.E911.Enabled,
		E911Provider:           p.E911.Provider,
		E911Websheet:           p.E911.Websheet,
		E911EntitlementEndpoint: p.E911.EntitlementEndpoint,
		RFOffDelay:             p.IKE.RFOffDelay,
		Blocked:                p.Blocked,
	}
}

// allEntries merges loaded external overrides and JSON profiles (including
// user overrides) for callers that need to scan every known preset.
// JSON profiles take priority over loaded overrides.
func allEntries() map[string]Preset {
	mu.RLock()
	merged := make(map[string]Preset, len(presets))
	for k, v := range presets {
		merged[k] = v
	}
	mu.RUnlock()
	// JSON profiles (including user overrides) take priority
	if all, err := All(); err == nil {
		for k, p := range all {
			merged[k] = carrierProfileToPreset(p)
		}
	}
	return merged
}

// ResolveEffectiveCarrierConfig returns the override for the given PLMN, or a
// zero-value config (PresetID "3gpp-default") when nothing overrides it.
// JSON profiles (including user overrides) take priority over loaded overrides.
func ResolveEffectiveCarrierConfig(input EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	cfg := EffectiveCarrierConfig{PresetID: "3gpp-default"}
	preset, ok := lookupWithJSON(input.MCC, input.MNC, input.SPN)
	if !ok {
		return cfg
	}
	if id := strings.TrimSpace(preset.ID); id != "" {
		cfg.PresetID = id
	} else {
		cfg.PresetID = plmnKey(input.MCC, input.MNC)
	}
	cfg.EPDGAddr = strings.TrimSpace(preset.EPDGAddr)
	cfg.AKAAppPreference = strings.TrimSpace(preset.AKAAppPreference)
	cfg.RFOffDelay = preset.RFOffDelay
	cfg.E911.Enabled = preset.E911Enabled
	cfg.E911.Provider = strings.TrimSpace(preset.E911Provider)
	cfg.E911.Websheet = strings.TrimSpace(preset.E911Websheet)
	cfg.E911.EntitlementEndpoint = strings.TrimSpace(preset.E911EntitlementEndpoint)
	return cfg
}

// IsVoWiFiBlockedMCC reports whether this MCC is policy-blocked outright
// (blockedMCCs), or whether any loaded/built-in preset under it is explicitly
// marked blocked. The orchestrator only has MCC at the point it calls this
// (pre-IMSI-parse), so a per-preset block only fires for a deliberately
// configured entry, never as an accidental default.
func IsVoWiFiBlockedMCC(mcc string) bool {
	mcc = strings.TrimSpace(mcc)
	if mcc == "" {
		return false
	}
	if blockedMCCs[mcc] {
		return true
	}
	for key, p := range allEntries() {
		if p.Blocked && strings.HasPrefix(key, mcc+"-") {
			return true
		}
	}
	return false
}

type blockedMCCError struct{ mcc string }

func (e *blockedMCCError) Error() string {
	return fmt.Sprintf("vowifi blocked by carrier policy for mcc %s", e.mcc)
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return &blockedMCCError{mcc: strings.TrimSpace(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	_, ok := err.(*blockedMCCError)
	return ok
}
