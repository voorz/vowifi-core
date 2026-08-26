package carrier

import (
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// ProfileToIMSFields wraps a CarrierProfile into voiceclient.IMSProfileFields
// so that voiceclient.CarrierProfileToRegisterProfile can consume it without
// vohive-next needing to know about the adapter.
func ProfileToIMSFields(p *CarrierProfile) voiceclient.IMSProfileFields {
	if p == nil {
		return nil
	}
	return carrierProfileIMSAdapter{p}
}

// init injects the carrier profile lookup function into voiceclient to avoid
// an import cycle (carrier → voiceclient → carrier).
func init() {
	voiceclient.SetProfileLookupFunc(func(mcc, mnc, spn string) (voiceclient.IMSProfileFields, bool) {
		p, err := LookupWithSPN(mcc, mnc, spn)
		if err != nil || p == nil {
			return nil, false
		}
		return carrierProfileIMSAdapter{p}, true
	})
}

// carrierProfileIMSAdapter wraps *CarrierProfile to implement
// voiceclient.IMSProfileFields without voiceclient needing to import carrier.
type carrierProfileIMSAdapter struct {
	p *CarrierProfile
}

func (a carrierProfileIMSAdapter) GetIMS() voiceclient.IMSProfileData {
	ims := a.p.IMS
	return voiceclient.IMSProfileData{
		ContactFeatures:           ims.ContactFeatures,
		IncludeAcceptContact:      ims.IncludeAcceptContact,
		IncludePPreferredID:       ims.IncludePPreferredID,
		IncludePVisitedNetworkID:  ims.IncludePVisitedNetworkID,
		IncludePAccessNetworkInfo: ims.IncludePAccessNetworkInfo,
		IncludeRoute:              ims.IncludeRoute,
		IncludeCellularNetwork:    ims.IncludeCellularNetwork,
		IncludeSecurityClient:     ims.IncludeSecurityClient,
		IncludeRequireSecAgree:    ims.IncludeRequireSecAgree,
		InitialAuthorization:      ims.InitialAuthorization,
		SecurityClientFormat:      ims.SecurityClientFormat,
		SupportedHeader:           ims.SupportedHeader,
		AllowHeader:               ims.AllowHeader,
		ICSIRef:                   ims.ICSIRef,
		IncludePANIAuthenticated:  ims.IncludePANIAuthenticated,
		UserAgent:                 ims.UserAgent,
		ContactUserRandom:         ims.ContactUserRandom,
		Expires:                   ims.Expires,
		VoiceSupportedHeader:      ims.VoiceSupportedHeader,
		VoiceAllowHeader:          ims.VoiceAllowHeader,
		VoiceAcceptContact:        ims.VoiceAcceptContact,
		VoicePPreferredService:    ims.VoicePPreferredService,
		AuthorizationIdentity:     ims.AuthorizationIdentity,
	}
}
