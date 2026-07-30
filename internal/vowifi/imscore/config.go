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

	Template policy.IMSRegisterTemplate

	MCC    string
	MNC    string
	CellID string

	SIPInstanceURN string
	UserAgent      string

	RegisterExpirySeconds int

	DeliveryStore   messaging.DeliveryStore
	Dispatcher       eventhost.Dispatcher

	// OnIMSReady is called after IMS REGISTER succeeds and the secure
	// messaging channel is attached. It gives the caller access to the
	// voiceclient.Client so it can create a voicehost.IMSOutboundAgent
	// for VoWiFi voice calls.
	OnIMSReady func(client *voiceclient.Client, deviceID string)

	// OnInboundCall is called when an inbound INVITE arrives from the IMS
	// network. Uses primitive types to avoid a circular dependency on
	// runtimehost.InboundCallRequest. The runtimehost layer adapts this
	// to its typed callback.
	OnInboundCall func(ctx context.Context, deviceID, callID, callerURI, calleeURI string, remoteSDP []byte) (statusCode int, reason string, sdp []byte, err error)
}
