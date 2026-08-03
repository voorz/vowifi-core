// Package profiles provides carrier profile loading from embedded JSON files.
//
// The profiles/ directory contains one JSON file per PLMN (e.g. 234-10.json for
// giffgaff UK). Each file follows the CarrierProfile schema defined in
// DESIGN_CARRIER_CONFIG.md. At init time all files are embedded and parsed; lookups
// are in-memory with zero file I/O at runtime.
package profiles

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed *.json
var profileFS embed.FS

// CarrierProfile is the unified carrier configuration matching the JSON schema.
// All fields are optional (omitempty); zero values mean "use 3GPP standard default".
type CarrierProfile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	MCC    string `json:"mcc"`
	MNC    string `json:"mnc"`
	IKE    IKEConfig    `json:"ike"`
	EAP    EAPConfig    `json:"eap"`
	IMS    IMSConfig    `json:"ims"`
	E911   E911Config   `json:"e911"`
	Device DeviceConfig `json:"device"`
	Blocked bool        `json:"blocked"`
}

type IKEConfig struct {
	Addr                   string   `json:"addr,omitempty"`
	Port                   int      `json:"port,omitempty"`
	Proposals              []string `json:"proposals,omitempty"`
	ESPProposals           []string `json:"esp_proposals,omitempty"`
	DPDInterval            int      `json:"dpd_interval,omitempty"`
	NATKeepalive           int      `json:"nat_keepalive,omitempty"`
	ReauthInterval         int      `json:"reauth_interval,omitempty"`
	IPStack                string   `json:"ip_stack,omitempty"`
	APN                    string   `json:"apn,omitempty"`
	ReplayWindow           int      `json:"replay_window,omitempty"`
	EnableESN              bool     `json:"enable_esn,omitempty"`
	DisableEAPMACValidation bool    `json:"disable_eap_mac_validation,omitempty"`
}

type EAPConfig struct {
	ChallengeMode        string `json:"challenge_mode,omitempty"`
	AppPreference        string `json:"app_preference,omitempty"`
	IdentitySource       string `json:"identity_source,omitempty"`
	DeviceIdentityEnabled *bool `json:"device_identity_enabled,omitempty"`
	DeviceModel          string `json:"device_model,omitempty"`
}

type IMSConfig struct {
	SecAgreeMode                           string                   `json:"sec_agree_mode,omitempty"`
	RequireSecAgree                        bool                     `json:"require_sec_agree,omitempty"`
	ProxyRequireSecAgree                   bool                     `json:"proxy_require_sec_agree,omitempty"`
	UsePlainDigestPlaceholder              bool                     `json:"use_plain_digest_placeholder,omitempty"`
	InitialAuthorization                   string                   `json:"initial_authorization,omitempty"`
	IncludePANI                            bool                     `json:"include_pani,omitempty"`
	IncludePANIAuthenticated               bool                     `json:"include_pani_authenticated,omitempty"`
	FixedPANI                              string                   `json:"fixed_pani,omitempty"`
	UserAgent                              string                   `json:"user_agent,omitempty"`
	SupportedHeader                        string                   `json:"supported_header,omitempty"`
	AllowHeader                            string                   `json:"allow_header,omitempty"`
	ContactParamOrder                      []string                 `json:"contact_param_order,omitempty"`
	ContactFeatures                        string                   `json:"contact_features,omitempty"`
	SecurityClientMechanisms               []SecurityMechanism      `json:"security_client_mechanisms,omitempty"`
	SecurityClientFormat                   string                   `json:"security_client_format,omitempty"`
	TransportMode                          string                   `json:"transport_mode,omitempty"`
	StrictSecurityServerOffer              bool                     `json:"strict_security_server_offer,omitempty"`
	EnableInitialRejectFallback            bool                     `json:"enable_initial_reject_fallback,omitempty"`
	OmitRoute                              bool                     `json:"omit_route,omitempty"`
	MinimalInitialHeaders                  bool                     `json:"minimal_initial_headers,omitempty"`
	ForceHeaderPort5060                    bool                     `json:"force_header_port_5060,omitempty"`
	OmitInitialSecurityClientProtocol      bool                     `json:"omit_initial_security_client_protocol,omitempty"`
	ProbeInitialSecurityClientOnBadRequest bool                     `json:"probe_initial_security_client_on_bad_request,omitempty"`
	IncludeConnectionKeepaliveInAuth       bool                     `json:"include_connection_keepalive_in_auth,omitempty"`
	SecurityClientIncludesServerParams     bool                     `json:"security_client_includes_server_params,omitempty"`
	FallbackIncludesServerParamsInSecCl    bool                     `json:"fallback_includes_server_params_in_sec_cl,omitempty"`
	Expires                                int                      `json:"expires,omitempty"`
	PCSCFAddr                              string                   `json:"pcscf_addr,omitempty"`
	Domain                                 string                   `json:"domain,omitempty"`
	Realm                                  string                   `json:"realm,omitempty"`
	AuthorizationIdentity                  string                   `json:"authorization_identity,omitempty"`
	IncludeAcceptContact                   bool                     `json:"include_accept_contact,omitempty"`
	IncludePPreferredID                    bool                     `json:"include_p_preferred_id,omitempty"`
	IncludePVisitedNetworkID               bool                     `json:"include_p_visited_network_id,omitempty"`
	IncludePAccessNetworkInfo              bool                     `json:"include_p_access_network_info,omitempty"`
	IncludeRoute                           bool                     `json:"include_route,omitempty"`
	IncludeCellularNetwork                 bool                     `json:"include_cellular_network,omitempty"`
	IncludeSecurityClient                  bool                     `json:"include_security_client,omitempty"`
	IncludeRequireSecAgree                 bool                     `json:"include_require_sec_agree,omitempty"`
	ContactUserRandom                      bool                     `json:"contact_user_random,omitempty"`
	ICSIRef                                string                   `json:"icsi_ref,omitempty"`
	VoiceSupportedHeader                   string                   `json:"voice_supported_header,omitempty"`
	VoiceAllowHeader                       string                   `json:"voice_allow_header,omitempty"`
	VoiceAcceptContact                     string                   `json:"voice_accept_contact,omitempty"`
	VoicePPreferredService                 string                   `json:"voice_p_preferred_service,omitempty"`
	IKEGatewayPrefixScores                 []GatewayPrefixScore     `json:"ike_gateway_prefix_scores,omitempty"`
	TCPKeepaliveSeconds                    int                      `json:"tcp_keepalive_seconds,omitempty"`
	OptionsPingIntervalSeconds             int                      `json:"options_ping_interval_seconds,omitempty"`
	LocalPort                              int                      `json:"local_port,omitempty"`
	RegisterPolicy                         *RegisterPolicy          `json:"register_policy,omitempty"`
}

type SecurityMechanism struct {
	Alg  string `json:"alg,omitempty"`
	EAlg string `json:"ealg,omitempty"`
	Prot string `json:"prot,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type GatewayPrefixScore struct {
	Prefix string `json:"prefix"`
	Score  int    `json:"score"`
}

type RegisterPolicy struct {
	ID                              string `json:"id,omitempty"`
	TemporaryStatusCodes            []int  `json:"temporary_status_codes,omitempty"`
	ForbiddenStatusCodes            []int  `json:"forbidden_status_codes,omitempty"`
	InitialRejectFallbackStatusCodes []int `json:"initial_reject_fallback_status_codes,omitempty"`
	TemporaryRetrySeconds           int    `json:"temporary_retry_seconds,omitempty"`
}

type E911Config struct {
	Enabled             bool   `json:"enabled,omitempty"`
	Provider            string `json:"provider,omitempty"`
	Websheet            string `json:"websheet,omitempty"`
	EntitlementEndpoint string `json:"entitlement_endpoint,omitempty"`
}

type DeviceConfig struct {
	IMEI              string `json:"imei,omitempty"`
	IMSTAC            int    `json:"ims_tac,omitempty"`
	IMSCellID         int    `json:"ims_cell_id,omitempty"`
	IMSCellIDMode     string `json:"ims_cell_id_mode,omitempty"`
	IMSRegisterProfile string `json:"ims_register_profile,omitempty"`
}

// plmnAliases maps MNC aliases to their canonical PLMN key.
// For example, China Mobile uses MNC 0/2/4/7 which all share the same template.
var plmnAliases = map[string]string{
	"460-2":  "460-0",  // CMCC alias
	"460-4":  "460-0",  // CMCC alias
	"460-7":  "460-0",  // CMCC alias
	"460-6":  "460-1",  // China Unicom alias
	"460-9":  "460-1",  // China Unicom alias
	"460-5":  "460-3",  // China Telecom alias
}

var (
	once     sync.Once
	profiles map[string]*CarrierProfile
	loadErr  error
)

// normalizeMNC strips leading zeros so "010" and "10" resolve to the same key.
func normalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	trimmed := strings.TrimLeft(mnc, "0")
	if trimmed == "" && mnc != "" {
		return "0"
	}
	return trimmed
}

func plmnKey(mcc, mnc string) string {
	return strings.TrimSpace(mcc) + "-" + normalizeMNC(mnc)
}

// load parses all embedded JSON files once at first use.
func load() {
	once.Do(func() {
		profiles = make(map[string]*CarrierProfile)
		entries, err := profileFS.ReadDir(".")
		if err != nil {
			loadErr = fmt.Errorf("profiles: read embed dir: %w", err)
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			if entry.Name() == "generic.json" {
				continue // generic is loaded separately
			}
			data, err := profileFS.ReadFile(entry.Name())
			if err != nil {
				loadErr = fmt.Errorf("profiles: read %s: %w", entry.Name(), err)
				return
			}
			var p CarrierProfile
			if err := json.Unmarshal(data, &p); err != nil {
				loadErr = fmt.Errorf("profiles: parse %s: %w", entry.Name(), err)
				return
			}
			key := plmnKey(p.MCC, p.MNC)
			profiles[key] = &p
		}
	})
}

// Lookup returns the carrier profile for the given PLMN, or nil if not found.
// MNC is normalized (leading zeros stripped) and aliases are resolved.
func Lookup(mcc, mnc string) (*CarrierProfile, error) {
	load()
	if loadErr != nil {
		return nil, loadErr
	}
	key := plmnKey(mcc, mnc)
	if alias, ok := plmnAliases[key]; ok {
		key = alias
	}
	return profiles[key], nil
}

// Generic returns the 3GPP standard default profile.
func Generic() (*CarrierProfile, error) {
	load()
	if loadErr != nil {
		return nil, loadErr
	}
	data, err := profileFS.ReadFile("generic.json")
	if err != nil {
		return nil, fmt.Errorf("profiles: read generic.json: %w", err)
	}
	var p CarrierProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("profiles: parse generic.json: %w", err)
	}
	return &p, nil
}

// All returns all loaded carrier profiles (excluding generic).
func All() (map[string]*CarrierProfile, error) {
	load()
	if loadErr != nil {
		return nil, loadErr
	}
	out := make(map[string]*CarrierProfile, len(profiles))
	for k, v := range profiles {
		out[k] = v
	}
	return out, nil
}
