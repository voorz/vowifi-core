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
// when no carrier-specific template matches. It contains only standards-compliant
// fields with no carrier-specific behavior, letting the ePDG/P-CSCF negotiate
// the rest. Carrier-specific templates (GiffgaffTemplate, VodafoneUKTemplate,
// eeUKBaseTemplate, etc.) override this for known PLMNs.
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
// home PLMN while keeping the existing generic fallback for unknown carriers.
func ResolveIMSRegisterTemplate(mcc, mnc string) IMSRegisterTemplate {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimLeft(strings.TrimSpace(mnc), "0")
	if mnc == "" {
		mnc = "0"
	}
	switch mcc + ":" + mnc {
	case "234:30":
		return EEUKTemplate()
	case "234:33":
		return CMlinkUKTemplate()
	case "234:15":
		return VodafoneUKTemplate()
	case "234:10":
		return GiffgaffTemplate()
	case "234:20":
		return ThreeUKTemplate()
	case "310:260", "310:240":
		return TMobileUSTemplate()
	case "310:280", "310:410":
		return ATTTemplate()
	case "204:4":
		return VodafoneNLTemplate()
	case "530:5":
		return SparkNZTemplate()
	case "530:24":
		return TwoDegreesNZTemplate()
	case "530:1":
		return OneNZTemplate()
	case "262:3", "262:7":
		return O2DETemplate()
	case "454:3":
		return ThreeHKTemplate()
	case "454:0":
		return CSLHKTemplate()
	case "228:2":
		return SunriseCHTemplate()
	}
	return GenericTemplate()
}
// embedded author binary carrier registry.
func GiffgaffTemplate() IMSRegisterTemplate {
	mechanisms := DefaultSecurityClientMechanisms()
	return IMSRegisterTemplate{
		ID:                          "giffgaff",
		SecAgreeMode:                "auto",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: false,
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: mechanisms,
	}
}
// VodafoneUKTemplate matches Vodafone UK's Qualcomm IMS profile: the first
// REGISTER advertises sec-agree and carries an empty AKA Authorization profile.
func VodafoneUKTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                                     "vodafone_uk_23415",
		SecAgreeMode:                           "on",
		IncludePANI:                            false,
		IncludePANIAuthenticated:               false,
		StrictSecurityServerOffer:              true,
		UsePlainDigestPlaceholder:              true,
		EnableInitialRejectFallback:            false,
		OmitRoute:                              true,
		MinimalInitialHeaders:                  true,
		RequireSecAgree:                        false,
		ProxyRequireSecAgree:                   false,
		OmitInitialSecurityClientProtocol:      false,
		ProbeInitialSecurityClientOnBadRequest: true,
		UserAgent:                              "Vodafone VOLTE Qualcomm",
		SupportedHeader:                        "path,sec-agree",
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
			"reg_id",
		},
		SecurityClientMechanisms: DefaultSecurityClientMechanisms(),
	}
}

// eeUKBaseTemplate 旧版多参数实现，排障期间使用但未成功，保留供回退
/*
func eeUKBaseTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                                     "cmlink_23433",
		SecAgreeMode:                           "on",
		UserAgent:                              "iOS/26.6 iPhone",
		FixedPANI:                              `IEEE-802.11; i-wlan-node-id="000000000000";country=GB`,
		IncludePANI:                            true,
		IncludePANIAuthenticated:                true,
		StrictSecurityServerOffer:              true,
		UsePlainDigestPlaceholder:              false,
		EnableInitialRejectFallback:            false,
		OmitRoute:                              false,
		MinimalInitialHeaders:                  true,
		ProbeInitialSecurityClientOnBadRequest: true,
		SupportedHeader:                        "path,sec-agree,gruu",
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		SecurityClientMechanisms: DefaultSecurityClientMechanisms(),
		TransportModes:          []string{"tcp", "udp"},
	}
}
*/
// eeUKBaseTemplate is the common IMS REGISTER template for EE UK and its MVNOs
// (CMlink UK, CTE UK). Key behaviors:
//   - IncludePANI: true with fixed IEEE-802.11 PANI for WiFi access
//   - UsePlainDigestPlaceholder: true for initial REGISTER
//   - SupportedHeader: path,sec-agree (no gruu)
//   - AllowHeader: REGISTER,INVITE,MESSAGE,SUBSCRIBE
func eeUKBaseTemplate(id string) IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                          id,
		EnableInitialRejectFallback: false,
		IncludePANIAuthenticated:    false,
		IncludePANI:                 true,
		FixedPANI:                   `IEEE-802.11; i-wlan-node-id="000000000000";country=GB`,
		UsePlainDigestPlaceholder:   true,
		SupportedHeader:             "path,sec-agree",
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
		AllowHeader:              "REGISTER,INVITE,MESSAGE,SUBSCRIBE",
		SecurityClientMechanisms: DefaultSecurityClientMechanisms(),
	}
}

// EEUKTemplate is the EE UK host network template (PLMN 234/30).
func EEUKTemplate() IMSRegisterTemplate {
	return eeUKBaseTemplate("ee_uk_23430")
}

// CMlinkUKTemplate is the China Mobile (CMLink) UK template (PLMN 234/33),
// an EE MVNO.
func CMlinkUKTemplate() IMSRegisterTemplate {
	return eeUKBaseTemplate("cmlink_uk_23433")
}

// CTEUKTemplate is the China Telecom UK template, an EE MVNO.
func CTEUKTemplate() IMSRegisterTemplate {
	return eeUKBaseTemplate("cte_uk")
}

// ThreeUKTemplate matches three_uk_234020.yaml from v1.5.5.
func ThreeUKTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                          "three_uk_234020",
		AllowHeader:                 "INVITE,BYE,CANCEL,ACK,NOTIFY,UPDATE,PRACK,INFO,MESSAGE,OPTIONS",
		ICSIRef:                     "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: false,
		SecurityClientMechanisms: []IPSec3GPPSecurityMechanism{
			{Alg: "hmac-sha-1-96", EAlg: "null", Prot: "esp", Mode: "trans"},
		},
		ContactParamOrder: []string{
			"access_type",
			"audio",
			"smsip",
			"icsi_ref",
			"sip_instance",
		},
	}
}

// TMobileUSTemplate matches T-Mobile_260.yaml / T-Mobile_240.yaml from v1.5.5.
// These presets specify only ESP proposals + E911; no ims_register_template.
func TMobileUSTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID: "T-Mobile_260",
	}
}

// ATTTemplate matches att_310280.yaml from v1.5.5. LycaMobile_310410 shares
// the same template (ims_register_template.id: att_310280).
func ATTTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                          "att_310280",
		SupportedHeader:             "path,sec-agree,gruu",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: true,
		SecurityClientMechanisms: []IPSec3GPPSecurityMechanism{
			{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Prot: "esp", Mode: "trans"},
		},
		RegisterPolicy: IMSRegisterPolicy{
			ID:                               "att_main",
			TemporaryStatusCodes:             []int{403, 480, 500, 503, 504},
			ForbiddenStatusCodes:             []int{},
			InitialRejectFallbackStatusCodes: []int{400, 403, 480, 500},
			TemporaryRetrySeconds:            0,
		},
	}
}

// VodafoneNLTemplate matches vodafone_nl_20404.yaml from v1.5.5.
func VodafoneNLTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                          "vodafone_nl_20404_ios",
		EnableInitialRejectFallback: false,
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		UsePlainDigestPlaceholder:   false,
	}
}

// SparkNZTemplate matches spark_nz_53005.yaml from v1.5.5.
// Preset specifies only ePDG + IMS domain; no register template fields.
func SparkNZTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID: "spark_nz_53005_ios",
	}
}

// TwoDegreesNZTemplate matches 2degrees_nz_53024.yaml from v1.5.5.
func TwoDegreesNZTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID: "2degrees_nz_53024_ios",
	}
}

// OneNZTemplate matches one_nz_53001.yaml from v1.5.5.
// Preset specifies only device_identity_enabled: false.
func OneNZTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID: "one_nz_53001",
	}
}

// O2DETemplate matches O2_de_26203.yaml from v1.5.5.
// O2_de_26207_alias.yaml shares the same template (id: O2_de_26203).
func O2DETemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:                          "O2_de_26203",
		IncludePANIAuthenticated:    true,
		StrictSecurityServerOffer:   true,
		EnableInitialRejectFallback: true,
	}
}

// ThreeHKTemplate matches three_hk_454003.yaml from v1.5.5.
func ThreeHKTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:           "three_hk_454003",
		SecAgreeMode: "auto",
	}
}

// CSLHKTemplate matches csl_454000.yaml from v1.5.5.
func CSLHKTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID:           "csl_454000",
		SecAgreeMode: "auto",
	}
}

// SunriseCHTemplate matches sunrise_22802.yaml from v1.5.5.
// Preset specifies only IKE/ESP proposals + aka_challenge_mode; no register template.
func SunriseCHTemplate() IMSRegisterTemplate {
	return IMSRegisterTemplate{
		ID: "sunrise_22802",
	}
}
