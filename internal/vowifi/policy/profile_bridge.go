package policy

import (
	"strings"

	"github.com/voorz/vowifi-core/profiles"
)

// ResolveIMSRegisterTemplateFromProfile attempts to load an IMS register template
// from the embedded JSON profiles. It returns the template and true if found,
// or a zero template and false if no profile exists for the PLMN.
//
// This is the JSON-first path; callers fall back to the hardcoded switch-case
// in ResolveIMSRegisterTemplate when this returns false.
func ResolveIMSRegisterTemplateFromProfile(mcc, mnc string) (IMSRegisterTemplate, bool) {
	p, err := profiles.Lookup(mcc, mnc)
	if err != nil || p == nil {
		return IMSRegisterTemplate{}, false
	}
	return carrierProfileToTemplate(p), true
}

func carrierProfileToTemplate(p *profiles.CarrierProfile) IMSRegisterTemplate {
	t := IMSRegisterTemplate{
		ID:                                     p.ID,
		UsePlainDigestPlaceholder:              p.IMS.UsePlainDigestPlaceholder,
		Expires:                                p.IMS.Expires,
		FixedPANI:                              p.IMS.FixedPANI,
		SupportedHeader:                        p.IMS.SupportedHeader,
		AllowHeader:                            p.IMS.AllowHeader,
		ICSIRef:                                p.IMS.ICSIRef,
		ContactParamOrder:                      p.IMS.ContactParamOrder,
		VoiceSupportedHeader:                   p.IMS.VoiceSupportedHeader,
		VoiceAllowHeader:                       p.IMS.VoiceAllowHeader,
		VoiceAcceptContact:                     p.IMS.VoiceAcceptContact,
		VoicePPreferredService:                 p.IMS.VoicePPreferredService,
		UserAgent:                              p.IMS.UserAgent,
		ForceHeaderPort5060:                    p.IMS.ForceHeaderPort5060,
		OmitRoute:                              p.IMS.OmitRoute,
		MinimalInitialHeaders:                  p.IMS.MinimalInitialHeaders,
		RequireSecAgree:                        p.IMS.RequireSecAgree,
		ProxyRequireSecAgree:                   p.IMS.ProxyRequireSecAgree,
		OmitInitialSecurityClientProtocol:      p.IMS.OmitInitialSecurityClientProtocol,
		ProbeInitialSecurityClientOnBadRequest: p.IMS.ProbeInitialSecurityClientOnBadRequest,
		IncludePANI:                            p.IMS.IncludePANI,
		IncludePANIAuthenticated:               p.IMS.IncludePANIAuthenticated,
		IncludeConnectionKeepaliveInAuth:       p.IMS.IncludeConnectionKeepaliveInAuth,
		SecAgreeMode:                           p.IMS.SecAgreeMode,
		SecurityClientIncludesServerParams:     p.IMS.SecurityClientIncludesServerParams,
		StrictSecurityServerOffer:              p.IMS.StrictSecurityServerOffer,
		EnableInitialRejectFallback:            p.IMS.EnableInitialRejectFallback,
		FallbackIncludesServerParamsInSecCl:    p.IMS.FallbackIncludesServerParamsInSecCl,
		TransportModes:                         nil, // handled by caller
	}

	// Convert security client mechanisms
	if len(p.IMS.SecurityClientMechanisms) > 0 {
		t.SecurityClientMechanisms = make([]IPSec3GPPSecurityMechanism, len(p.IMS.SecurityClientMechanisms))
		for i, m := range p.IMS.SecurityClientMechanisms {
			t.SecurityClientMechanisms[i] = IPSec3GPPSecurityMechanism{
				Alg:  m.Alg,
				EAlg: m.EAlg,
				Prot: m.Prot,
				Mode: m.Mode,
			}
		}
	}

	// Convert transport modes
	if mode := strings.TrimSpace(p.IMS.TransportMode); mode != "" {
		t.TransportModes = []string{mode}
	}

	// Convert register policy
	if p.IMS.RegisterPolicy != nil {
		t.RegisterPolicy = IMSRegisterPolicy{
			ID:                              p.IMS.RegisterPolicy.ID,
			TemporaryStatusCodes:            p.IMS.RegisterPolicy.TemporaryStatusCodes,
			ForbiddenStatusCodes:            p.IMS.RegisterPolicy.ForbiddenStatusCodes,
			InitialRejectFallbackStatusCodes: p.IMS.RegisterPolicy.InitialRejectFallbackStatusCodes,
			TemporaryRetrySeconds:           p.IMS.RegisterPolicy.TemporaryRetrySeconds,
		}
	}

	// Convert IKE gateway prefix scores
	if len(p.IMS.IKEGatewayPrefixScores) > 0 {
		t.IKEGatewayPrefixScores = make([]IKEGatewayPrefixScore, len(p.IMS.IKEGatewayPrefixScores))
		for i, s := range p.IMS.IKEGatewayPrefixScores {
			t.IKEGatewayPrefixScores[i] = IKEGatewayPrefixScore{
				Prefix: s.Prefix,
				Score:  s.Score,
			}
		}
	}

	return t
}
