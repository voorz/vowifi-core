package carrier

import (
	"fmt"
	"strings"
)

// formatUTRANCellIDSuffix returns the hex suffix (TAC + ECI) used after the home
// PLMN in utran-cell-id-3gpp. When both inputs are zero an empty string is
// returned so callers can fall back to the SimAdmin-style placeholder.
//
// This is a local copy of voiceclient.FormatUTRANCellIDSuffix to avoid an
// import cycle (carrier → voiceclient → carrier).
func formatUTRANCellIDSuffix(tac, eci uint32) string {
	if tac == 0 && eci == 0 {
		return ""
	}
	return fmt.Sprintf("%04X%07X", tac&0xFFFF, eci&0x0FFFFFFF)
}

// DefaultUTRANCellIDSuffix returns the configured utran-cell-id-3gpp suffix
// (TAC+ECI hex, without PLMN) for a PLMN when live QMI readings are unavailable.
func DefaultUTRANCellIDSuffix(mcc, mnc, spn string) string {
	preset, ok := lookupWithJSON(mcc, mnc, spn)
	if !ok {
		return ""
	}
	return presetUTRANCellIDSuffix(preset)
}

func presetUTRANCellIDSuffix(p Preset) string {
	if suffix := formatUTRANCellIDSuffix(p.IMSTAC, p.IMSCellID); suffix != "" {
		return suffix
	}
	return ""
}

// IMSCellIDMode returns the configured cell-id selection mode for a PLMN.
// Empty string means qmi_first.
func IMSCellIDMode(mcc, mnc, spn string) string {
	preset, ok := lookupWithJSON(mcc, mnc, spn)
	if !ok {
		return ""
	}
	return normalizeIMSCellIDMode(preset.IMSCellIDMode)
}

func normalizeIMSCellIDMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "carrier_only", "none":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "qmi_first"
	}
}
