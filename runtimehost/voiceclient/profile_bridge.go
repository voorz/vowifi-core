package voiceclient

import (
	"strings"
)

// IMSProfileFields is the subset of carrier.CarrierProfile needed by
// CarrierProfileToRegisterProfile. Defined as an interface to avoid an
// import cycle (carrier → voiceclient → carrier).
type IMSProfileFields interface {
	GetIMS() IMSProfileData
}

// IMSProfileData is a value type implementing IMSProfileFields.
// carrier.CarrierProfile satisfies this via a shim in carrier/ims_shim.go.
type IMSProfileData struct {
	ContactFeatures           string
	IncludeAcceptContact      bool
	IncludePPreferredID       bool
	IncludePVisitedNetworkID  bool
	IncludePAccessNetworkInfo bool
	IncludeRoute              bool
	IncludeCellularNetwork    bool
	IncludeSecurityClient     bool
	IncludeRequireSecAgree    bool
	InitialAuthorization      string
	SecurityClientFormat      string
	SupportedHeader           string
	AllowHeader               string
	ICSIRef                   string
	IncludePANIAuthenticated  bool
	UserAgent                 string
	ContactUserRandom         bool
	Expires                   int
	VoiceSupportedHeader      string
	VoiceAllowHeader          string
	VoiceAcceptContact        string
	VoicePPreferredService    string
	AuthorizationIdentity     string
}

func (d IMSProfileData) GetIMS() IMSProfileData { return d }

// registerProfileFromJSON attempts to load a RegisterProfile from a carrier profile.
// The profile lookup is injected by the caller (carrier package) to avoid an
// import cycle. See carrier/ims_shim.go for the bridge.
var profileLookupFunc func(mcc, mnc, spn string) (IMSProfileFields, bool)

// SetProfileLookupFunc injects the carrier profile lookup function.
// Called from carrier package init or vohive-next startup.
func SetProfileLookupFunc(f func(mcc, mnc, spn string) (IMSProfileFields, bool)) {
	profileLookupFunc = f
}

func registerProfileFromJSON(mcc, mnc, spn string) (RegisterProfile, bool) {
	if profileLookupFunc == nil {
		return RegisterProfile{}, false
	}
	p, ok := profileLookupFunc(mcc, mnc, spn)
	if !ok || p == nil {
		return RegisterProfile{}, false
	}
	return CarrierProfileToRegisterProfile(p), true
}

// CarrierProfileToRegisterProfile maps an IMSProfileFields to a
// voiceclient.RegisterProfile, translating all IMS REGISTER-related fields.
// Exported so that vohive-next can pre-populate StartRequest.RegisterProfile
// from the JSON carrier profile before runtimehost.Start is called.
func CarrierProfileToRegisterProfile(p IMSProfileFields) RegisterProfile {
	ims := p.GetIMS()
	rp := RegisterProfile{
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
		IcsiRef:                   ims.ICSIRef,
		IncludePANIAuthenticated:  ims.IncludePANIAuthenticated,
		UserAgent:                 ims.UserAgent,
		ContactUserRandom:         ims.ContactUserRandom,
		RegisterExpirySeconds:     ims.Expires,
		VoiceSupportedHeader:      ims.VoiceSupportedHeader,
		VoiceAllowHeader:          ims.VoiceAllowHeader,
		VoiceAcceptContact:        ims.VoiceAcceptContact,
		VoicePPreferredService:    ims.VoicePPreferredService,
	}
	if authID := strings.TrimSpace(ims.AuthorizationIdentity); authID != "" {
		rp.AuthorizationIdentity = authID
	}
	return rp
}
