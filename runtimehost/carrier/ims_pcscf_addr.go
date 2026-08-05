package carrier

import "strings"

// ResolveIMSPcscfAddr returns a carrier preset P-CSCF override ("host:port") when set.
func ResolveIMSPcscfAddr(mcc, mnc, spn string) string {
	preset, ok := lookupWithJSON(mcc, mnc, spn)
	if !ok {
		return ""
	}
	return strings.TrimSpace(preset.IMSPcscfAddr)
}
