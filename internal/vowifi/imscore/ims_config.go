package imscore

import (
	"net"
	"strings"

	"github.com/voorz/vowifi-core/engine/sim"
	"github.com/voorz/vowifi-core/internal/vowifi/policy"
	"github.com/voorz/vowifi-core/runtimehost/eventhost"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// IMSConfig is the author v1.1.2 imscore service configuration surface.
type IMSConfig struct {
	Enabled                    bool
	DeviceID                   string
	PCSCF                      string
	Registrar                  string
	Domain                     string
	Realm                      string
	IMPI                       string
	IMPU                       string
	CarrierPresetID            string
	IMSRegisterTemplate        policy.IMSRegisterTemplate
	IMSRegisterPolicySource    string
	LocalAddr                  string
	LocalPort                  int
	Transport                  string
	UserAgent                  string
	PAccessNetworkInfo         string
	CellularNetworkInfo        string
	SIPInstance                string
	IcsiRef                    string
	TCPKeepaliveSeconds        int
	OptionsPingIntervalSeconds int
	EnableIPSec3GPP            *bool
}

// DialOptions carries TCP dial tuning for IMSNetwork.DialContext.
type DialOptions struct {
	Timeout   int64
	KeepAlive int64
	TCPMSS    int
}

// StartSessionInput carries runtimehost session context not present on IMSConfig.
type StartSessionInput struct {
	TraceID               string
	LocalIP               net.IP
	Dataplane             voiceclient.PacketDataplane
	RegistrarCandidates   []string
	AKA                   sim.AKAProvider
	EAPRand               []byte // EAP-AKA Challenge RAND（供 IMS 预计算 AKA 复用）
	EAPAutn               []byte // EAP-AKA Challenge AUTN（供 IMS 预计算 AKA 复用）
	EAPRES                []byte // EAP-AKA Challenge RES（供 IMS eap_direct 模式复用）
	EAPCK                 []byte // EAP-AKA Challenge CK（供 IMS eap_direct 模式复用）
	EAPIK                 []byte // EAP-AKA Challenge IK（供 IMS eap_direct 模式复用）
	DeliveryStore         messaging.DeliveryStore
	Dispatcher            eventhost.Dispatcher
	IMSI                  string
	SMSC                  string
	MCC                   string
	MNC                   string
	CellID                string
	RegisterExpirySeconds int
	// ProgressCallback is invoked at key IMS REGISTER state-machine transitions
	// to report granular progress to the caller (e.g. runtimehost.Instance).
	ProgressCallback func(info RegisterProgress)
}

// RegisterProgress carries real-time IMS registration progress info.
type RegisterProgress struct {
	Stage          string // "ims_register", "ims_challenge", "ims_protected", "ims_ready", "ims_failed"
	StageLabel     string // human-readable description
	VariantIndex   int    // current variant index (0-based)
	VariantTotal   int    // total variants
	VariantName    string // current variant name
	ChallengeRound int    // AKA challenge round (1-based)
	SIPStatus      int    // last SIP status code received
	SIPReason      string // last SIP reason phrase
}

// IMSConfigFromVoice builds the author-facing IMSConfig from runtimehost inputs.
func IMSConfigFromVoice(v voiceclient.Config, template policy.IMSRegisterTemplate, presetID string) IMSConfig {
	transport := strings.TrimSpace(v.Transport)
	if transport == "" {
		transport = "auto"
	}
	policySource := "default"
	if id := strings.TrimSpace(template.RegisterPolicy.ID); id != "" {
		policySource = id
	}
	cfg := IMSConfig{
		Enabled:                 true,
		DeviceID:                strings.TrimSpace(v.DeviceID),
		PCSCF:                   strings.TrimSpace(v.PCSCFAddr),
		Registrar:               strings.TrimSpace(v.PCSCFAddr),
		Domain:                  strings.TrimSpace(v.HomeDomain),
		Realm:                   strings.TrimSpace(v.Realm),
		IMPI:                    strings.TrimSpace(v.PrivateID),
		IMPU:                    strings.TrimSpace(v.PublicURI),
		CarrierPresetID:         strings.TrimSpace(presetID),
		IMSRegisterTemplate:     template,
		IMSRegisterPolicySource: policySource,
		Transport:               transport,
		TCPKeepaliveSeconds:        template.TCPKeepaliveSeconds,
		OptionsPingIntervalSeconds: template.OptionsPingIntervalSeconds,
		UserAgent:               strings.TrimSpace(v.RegisterProfile.UserAgent),
		SIPInstance:             strings.TrimSpace(v.SIPInstanceURN),
	}
	if v.LocalIP != nil {
		cfg.LocalAddr = v.LocalIP.String()
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Apple iPhone17,2/26.6 (17,2; iOS 26.6; 23G82) Boot/3.0.0 VoIP/1.0 Carrier/59.0"
	}
	if strings.TrimSpace(cfg.CarrierPresetID) == "" {
		cfg.CarrierPresetID = "3gpp-default"
	}
	if strings.TrimSpace(cfg.IMSRegisterTemplate.ID) == "" {
		cfg.IMSRegisterTemplate = policy.GenericTemplate()
	}
	return cfg
}

func internalConfigFromIMS(ims IMSConfig, in StartSessionInput) Config {
	pcscf := strings.TrimSpace(ims.PCSCF)
	if pcscf == "" {
		pcscf = strings.TrimSpace(ims.Registrar)
	}
	cfg := Config{
		DeviceID:              strings.TrimSpace(ims.DeviceID),
		TraceID:               strings.TrimSpace(in.TraceID),
		LocalIP:               in.LocalIP,
		Dataplane:             in.Dataplane,
		PCSCFAddr:             pcscf,
		RegistrarCandidates:   append([]string(nil), in.RegistrarCandidates...),
		Realm:                 strings.TrimSpace(ims.Realm),
		PrivateID:             strings.TrimSpace(ims.IMPI),
		PublicURI:             strings.TrimSpace(ims.IMPU),
		HomeDomain:            strings.TrimSpace(ims.Domain),
		IMSI:                  strings.TrimSpace(in.IMSI),
		SMSC:                  strings.TrimSpace(in.SMSC),
		AKA:                   in.AKA,
		EAPRand:               append([]byte(nil), in.EAPRand...),
		EAPAutn:               append([]byte(nil), in.EAPAutn...),
		EAPRES:                append([]byte(nil), in.EAPRES...),
		EAPCK:                 append([]byte(nil), in.EAPCK...),
		EAPIK:                 append([]byte(nil), in.EAPIK...),
		Template:              ims.IMSRegisterTemplate,
		DigestPassword:        strings.TrimSpace(ims.IMSRegisterTemplate.DigestPassword),
		MCC:                   strings.TrimSpace(in.MCC),
		MNC:                   strings.TrimSpace(in.MNC),
		CellID:                strings.TrimSpace(in.CellID),
		SIPInstanceURN:        strings.TrimSpace(ims.SIPInstance),
		UserAgent:             strings.TrimSpace(ims.UserAgent),
		RegisterExpirySeconds: in.RegisterExpirySeconds,
		DeliveryStore:         in.DeliveryStore,
		Dispatcher:            in.Dispatcher,
		TCPKeepaliveSeconds:        ims.TCPKeepaliveSeconds,
		OptionsPingIntervalSeconds: ims.OptionsPingIntervalSeconds,
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Apple iPhone17,2/26.6 (17,2; iOS 26.6; 23G82) Boot/3.0.0 VoIP/1.0 Carrier/59.0"
	}
	if strings.TrimSpace(cfg.Template.ID) == "" {
		cfg.Template = policy.GenericTemplate()
	}
	return cfg
}

func registerPolicyID(t policy.IMSRegisterTemplate) string {
	if id := strings.TrimSpace(t.RegisterPolicy.ID); id != "" {
		return id
	}
	return "default"
}
