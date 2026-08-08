package voiceclient

import (
	"strings"

	"github.com/voorz/vowifi-core/profiles"
)

// registerProfileFromJSON attempts to load a RegisterProfile from embedded JSON.
// Returns the profile and true if found, or zero value and false.
func registerProfileFromJSON(mcc, mnc, spn string) (RegisterProfile, bool) {
	p, err := profiles.LookupWithSPN(mcc, mnc, spn)
	if err != nil || p == nil {
		return RegisterProfile{}, false
	}
	return CarrierProfileToRegisterProfile(p), true
}

// CarrierProfileToRegisterProfile maps a profiles.CarrierProfile to a
// voiceclient.RegisterProfile, translating all IMS REGISTER-related fields.
// Exported so that vohive-next can pre-populate StartRequest.RegisterProfile
// from the JSON carrier profile before runtimehost.Start is called.
func CarrierProfileToRegisterProfile(p *profiles.CarrierProfile) RegisterProfile {
	rp := RegisterProfile{
		ContactFeatures:           p.IMS.ContactFeatures,
		IncludeAcceptContact:      p.IMS.IncludeAcceptContact,
		IncludePPreferredID:       p.IMS.IncludePPreferredID,
		IncludePVisitedNetworkID:  p.IMS.IncludePVisitedNetworkID,
		IncludePAccessNetworkInfo: p.IMS.IncludePAccessNetworkInfo,
		IncludeRoute:              p.IMS.IncludeRoute,
		IncludeCellularNetwork:    p.IMS.IncludeCellularNetwork,
		IncludeSecurityClient:     p.IMS.IncludeSecurityClient,
		IncludeRequireSecAgree:    p.IMS.IncludeRequireSecAgree,
		InitialAuthorization:      p.IMS.InitialAuthorization,
		SecurityClientFormat:      p.IMS.SecurityClientFormat,
		SupportedHeader:           p.IMS.SupportedHeader,
		AllowHeader:              p.IMS.AllowHeader,
		IcsiRef:                  p.IMS.ICSIRef,
		IncludePANIAuthenticated:  p.IMS.IncludePANIAuthenticated,
		UserAgent:                 p.IMS.UserAgent,
		ContactUserRandom:         p.IMS.ContactUserRandom,
		RegisterExpirySeconds:     p.IMS.Expires,
		VoiceSupportedHeader:      p.IMS.VoiceSupportedHeader,
		VoiceAllowHeader:          p.IMS.VoiceAllowHeader,
		VoiceAcceptContact:        p.IMS.VoiceAcceptContact,
		VoicePPreferredService:    p.IMS.VoicePPreferredService,
	}
	if authID := strings.TrimSpace(p.IMS.AuthorizationIdentity); authID != "" {
		rp.AuthorizationIdentity = authID
	}
	return rp
}
