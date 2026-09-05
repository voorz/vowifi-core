// Package carrier: carrier profile types and user override management.
//
// This file provides the CarrierProfile type definition and user override
// functions (SetUserOverrideByKey, etc.). The legacy 26 PLMN-keyed JSON
// files are kept in profiles-bak/ as backup only and are NOT embedded.
//
// Profile lookup is handled by lookup.go via GID-based matching against
// the 683 embedded carrier profiles. User overrides registered here take
// priority over embedded profiles.
package carrier

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// ProfileResolver resolves active carrier profiles from an external store (e.g. DB).
// The host application (vohive-next) injects an implementation at startup.
// If no resolver is injected, LookupWithSPN returns nil (fallback to embedded profiles).
type ProfileResolver interface {
	// LookupActiveProfile returns the active carrier profile for the given key,
	// or nil if no active profile exists.
	LookupActiveProfile(key string) (*CarrierProfile, error)
}

var (
	resolverOnce sync.Once
	resolver     ProfileResolver
)

// SetProfileResolver injects the DB-backed profile resolver.
// Must be called once at startup before any LookupWithSPN call.
func SetProfileResolver(r ProfileResolver) {
	resolverOnce.Do(func() {
		resolver = r
	})
}

//go:embed embed/generic.json
var genericProfileRaw []byte

// CarrierProfile is the unified carrier configuration matching the JSON schema.
// All fields are optional (omitempty); zero values mean "use 3GPP standard default".
type CarrierProfile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
// TemplateLevel identifies the source of this profile:
//   "default" — embedded system template (profiles/*.json or generic.json)
//   "user"    — user-defined override (DB carrier_templates)
	TemplateLevel string      `json:"template_level,omitempty"`
	MCC           string      `json:"mcc"`
	MNC           string      `json:"mnc"`
	IKE           IKEConfig   `json:"ike"`
	EAP           EAPConfig   `json:"eap"`
	IMS           IMSConfig   `json:"ims"`
	E911          E911Config  `json:"e911"`
	Device        DeviceConfig `json:"device"`
	Blocked       bool        `json:"blocked"`
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
	EAPMACValidation      bool     `json:"eap_mac_validation,omitempty"`
	RFOffDelay             int      `json:"rf_off_delay,omitempty"` // RFOff 后等待秒数（默认 5s），让 mihomo 路由表重建
	RekeyPFS               int      `json:"rekey_pfs,omitempty"`     // Child SA PFS DH 组 (如 14=MODP2048)，0=禁用
	TicketRequestEnabled   *bool    `json:"ticket_request,omitempty"`       // RFC 5723: N(TICKET_REQUEST) in first IKE_AUTH
	CPInFirstAuth          *bool    `json:"cp_in_first_auth,omitempty"`     // CP(CFG_REQUEST) in first IKE_AUTH
	CPInFinalAuth          *bool    `json:"cp_in_final_auth,omitempty"`      // CP(CFG_REQUEST) in final AUTH message (nil=true)
	CookiePayloadType      string   `json:"cookie_payload_type,omitempty"`   // COOKIE Notify 载荷类型: "notify"(默认N41) 或 "sa"(SA33, 兼容非标ePDG)
	AutoPRF                string   `json:"auto_prf,omitempty"`              // PRF 自动推导模式: ""(默认)/"auto"=从Integrity自动推导, "off"=不推导
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
	// DigestPassword is the IMS SIP Digest password used when the P-CSCF
	// returns algorithm=MD5 (non-AKA) challenges. Some MVNOs (e.g. CMLink UK)
	// use plain HTTP Digest authentication instead of AKAv1-MD5; their P-CSCF
	// rejects the empty-password digest this codebase would otherwise compute.
	// When non-empty, computeAKAAuth passes it through to simauth.ComputeDigest
	// so the MD5 response is calculated with the carrier-provided secret.
	// When empty, the existing empty-password behavior is preserved.
	DigestPassword                         string                  `json:"digest_password,omitempty"`
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
// Keys MUST use the same zero-padded format as PlmnKey (3-digit MNC).
// ⚠️ WARNING: Do NOT change MNC to stripped format. PlmnKey zero-pads MNC
// to 3 digits. If you change this to stripped format, LookupWithSPN will
// fail to match aliases and break carrier resolution. If you encounter
// matching issues, fix the root cause, do NOT strip zeros here.
var plmnAliases = map[string]string{
	"460-002": "460-000", // CMCC alias
	"460-004": "460-000", // CMCC alias
	"460-007": "460-000", // CMCC alias
	"460-006": "460-001", // China Unicom alias
	"460-009": "460-001", // China Unicom alias
	"460-005": "460-003", // China Telecom alias
}

// Lookup returns the carrier profile for the given PLMN, or nil if not found.
// Delegates to LookupWithSPN with empty SPN.
func Lookup(mcc, mnc string) (*CarrierProfile, error) {
	return LookupWithSPN(mcc, mnc, "")
}

// LookupWithSPN returns the active user-defined carrier profile for the given PLMN
// by querying the injected ProfileResolver (DB). Returns nil if no resolver is
// injected or no active profile exists (caller should use LookupWithIdentity
// or Generic for embedded profile lookup).
func LookupWithSPN(mcc, mnc, spn string) (*CarrierProfile, error) {
	if resolver == nil {
		return nil, nil
	}
	key := plmnKey(mcc, mnc)
	if alias, ok := plmnAliases[key]; ok {
		key = alias
	}
	// Try brand key first (e.g. "262-002__Vodafone DE")
	if spn != "" {
		brandKey := key + "__" + strings.TrimSpace(spn)
		if p, err := resolver.LookupActiveProfile(brandKey); err == nil && p != nil {
			if p.TemplateLevel == "" {
				p.TemplateLevel = "user"
			}
			return p, nil
		}
	}
	// Fallback to base PLMN key
	if p, err := resolver.LookupActiveProfile(key); err == nil && p != nil {
		if p.TemplateLevel == "" {
			p.TemplateLevel = "user"
		}
		return p, nil
	}
	return nil, nil
}

// Generic returns the 3GPP standard default profile from embedded generic.json.
// This is used as the final fallback when no carrier-specific profile matches.
var (
	genericOnce  sync.Once
	genericProf  *CarrierProfile
	genericErr   error
)

func Generic() (*CarrierProfile, error) {
	genericOnce.Do(func() {
		if err := json.Unmarshal(genericProfileRaw, &genericProf); err != nil {
			genericErr = fmt.Errorf("carrier: parse generic.json: %w", err)
			return
		}
		if genericProf != nil && genericProf.TemplateLevel == "" {
			genericProf.TemplateLevel = "default"
		}
	})
	if genericErr != nil {
		return nil, genericErr
	}
	if genericProf == nil {
		return &CarrierProfile{ID: "3gpp-default", TemplateLevel: "default"}, nil
	}
	return genericProf, nil
}


