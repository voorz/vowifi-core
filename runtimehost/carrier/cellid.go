package carrier

import (
	"strings"

	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

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
	if suffix := voiceclient.FormatUTRANCellIDSuffix(p.IMSTAC, p.IMSCellID); suffix != "" {
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
