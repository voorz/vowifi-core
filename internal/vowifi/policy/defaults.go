package policy

import "strings"

// DefaultSecurityClientMechanisms returns the standard 6-mechanism phone-style
// Security-Client set used when a carrier preset does not override mechanisms.
func DefaultSecurityClientMechanisms() []IPSec3GPPSecurityMechanism {
	return []IPSec3GPPSecurityMechanism{
		{Alg: "hmac-md5-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-md5-96", EAlg: "aes-cbc"},
		{Alg: "hmac-md5-96", EAlg: "null"},
		{Alg: "hmac-sha-1-96", EAlg: "des-ede3-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "aes-cbc"},
		{Alg: "hmac-sha-1-96", EAlg: "null"},
	}
}

// DefaultIKEGatewayScore is the score assigned to ePDG gateway candidates whose
// IPv6 prefix does not match any entry in IKEGatewayPrefixScores.
const DefaultIKEGatewayScore = 30

// DefaultIKEGatewayPrefixScores returns the default IPv6 prefix priority table
// for ranking ePDG/P-CSCF gateway candidates. The 2a03:dd00: range belongs to
// EE UK; carriers that run on different infrastructure can override
// IKEGatewayPrefixScores in their template.
func DefaultIKEGatewayPrefixScores() []IKEGatewayPrefixScore {
	return []IKEGatewayPrefixScore{
		{Prefix: "2a03:dd00:1f80:", Score: 100},
		{Prefix: "2a03:dd00:1f81:810:", Score: 80},
		{Prefix: "2a03:dd00:1f81:10:", Score: 10},
		{Prefix: "2a03:dd00:1f81:5010:", Score: 10},
		{Prefix: "2a03:dd00:1f81:", Score: 40},
	}
}

// GenericTemplate is the 3GPP-standard default IMS REGISTER template used
// when no carrier-specific JSON profile matches. It contains only
// standards-compliant fields with no carrier-specific behavior, letting the
// ePDG/P-CSCF negotiate the rest. Carrier-specific profiles in profiles/*.json
// override this for known PLMNs.
func GenericTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                        "3gpp-default",
		SecAgreeMode:              "auto",
		StrictSecurityServerOffer: true,
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: DefaultSecurityClientMechanisms(),
		IKEGatewayPrefixScores:   DefaultIKEGatewayPrefixScores(),
	}
}

// ResolveIMSRegisterTemplate selects the IMS REGISTER behavior required by a
// home PLMN. Carrier-specific templates are loaded from embedded JSON profiles
// (profiles/*.json). Unknown PLMNs fall back to GenericTemplate (3GPP standard).
func ResolveIMSRegisterTemplate(mcc, mnc, spn string) IMSRegisterTemplate {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimLeft(strings.TrimSpace(mnc), "0")
	if mnc == "" {
		mnc = "0"
	}
	if t, ok := ResolveIMSRegisterTemplateFromProfile(mcc, mnc, spn); ok {
		return t
	}
	return GenericTemplate()
}

