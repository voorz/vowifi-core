package imscore

import (
	"context"
	"net"

	"github.com/voorz/vowifi-core/engine/sim"
	"github.com/voorz/vowifi-core/internal/vowifi/policy"
	"github.com/voorz/vowifi-core/runtimehost/eventhost"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// Config configures the RE-based imscore IMS register + messaging service.
type Config struct {
	DeviceID string
	TraceID  string

	LocalIP   net.IP
	Dataplane voiceclient.PacketDataplane
	PCSCFAddr string
	// TransportPCSCFAddr overrides the TCP destination for REGISTER when the
	// logical registrar (PCSCFAddr) is the UE inner IPv6 and userspace netstack
	// cannot hairpin to itself.
	TransportPCSCFAddr string
	// RegistrarCandidates is the ordered IKE/ePDG P-CSCF list used for initial
	// REGISTER probing when the first node returns a location/forbidden reject.
	RegistrarCandidates []string

	Realm      string
	PrivateID  string
	PublicURI  string
	HomeDomain string
	IMSI       string
	SMSC       string

	AKA sim.AKAProvider

	EAPRand []byte // EAP-AKA Challenge RAND（供预计算 AKA 复用）
	EAPAutn []byte // EAP-AKA Challenge AUTN（供预计算 AKA 复用）
	EAPRES  []byte // EAP-AKA Challenge RES（供 eap_direct 模式复用）
	EAPCK   []byte // EAP-AKA Challenge CK（供 eap_direct 模式复用）
	EAPIK   []byte // EAP-AKA Challenge IK（供 eap_direct 模式复用）

	Template policy.IMSRegisterTemplate

	DigestPassword string

	MCC    string
	MNC    string
	CellID string

	SIPInstanceURN string
	UserAgent      string

	RegisterExpirySeconds int

	DeliveryStore messaging.DeliveryStore
	Dispatcher    eventhost.Dispatcher

	// OnIMSReady is called after IMS REGISTER succeeds and the secure
	// messaging channel is attached. It gives the caller access to the
	// voiceclient.Client so it can create a voicehost.IMSOutboundAgent
	// for VoWiFi voice calls.
	OnIMSReady func(client *voiceclient.Client, deviceID string)

	// OnInboundCall is called when an inbound INVITE arrives from the IMS
	// network. Uses primitive types to avoid a circular dependency on
	// runtimehost.InboundCallRequest. The runtimehost layer adapts this
	// to its typed callback. The respond function allows the handler to
	// send provisional responses (e.g. 180 Ringing) before the final
	// response is returned.
	OnInboundCall func(ctx context.Context, deviceID, callID, callerURI, calleeURI string, remoteSDP []byte, respond func(statusCode int, reason string, sdp []byte) error) (statusCode int, reason string, sdp []byte, err error)

	// OnInboundBye is called when an inbound BYE arrives from the IMS
	// network (the remote party hangs up). The caller (vohive-next) should
	// forward the BYE to Linphone and close any associated relay. nil
	// disables BYE forwarding (IMS BYE gets 200 OK with no action).
	OnInboundBye func(ctx context.Context, deviceID, callID string) error

	// OnInboundCancel is called when an inbound CANCEL arrives from the
	// IMS network (the remote party cancels the call before it's answered).
	// The caller (vohive-next) should forward the CANCEL to Linphone and
	// clean up any associated relay. nil disables CANCEL forwarding.
	OnInboundCancel func(ctx context.Context, deviceID, callID string) error

	// TCPKeepaliveSeconds controls how often to send SIP OPTIONS keepalive on
	// the IMS TCP connection to prevent P-CSCF from closing idle connections.
	// 0 means use the default (15s). Negative disables.
	TCPKeepaliveSeconds int

// OptionsPingIntervalSeconds controls how often to send SIP OPTIONS
// ping as a higher-level liveness check. 0 means use the default (30s).
// Negative disables. This is complementary to TCPKeepaliveSeconds.
OptionsPingIntervalSeconds int

	// OnIMSConnDown is called when the IMS TCP connection to the P-CSCF is
	// closed (EOF, reset, or read error). The caller should trigger pipeline
	// recovery (re-establish SWu tunnel + re-REGISTER). nil disables.
	// Per 改动点 5 spec.
	OnIMSConnDown func()
}
