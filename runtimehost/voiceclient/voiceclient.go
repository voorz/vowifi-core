// Package voiceclient provides IMS configuration types and SWu transport
// abstractions for VoWiFi. After the architecture refactoring (阶段0),
// all SIP runtime logic (REGISTER, keepalive, SMS, USSD) has been moved
// to imscore.Service. This package now only retains:
//
//   - Config: IMS configuration container
//   - RegisterProfile: carrier-specific REGISTER header configuration
//   - SWUTCPDialer / PacketDataplane: SWu transport abstractions
//   - SWu netstack / packetconn: userspace transport layer
//   - Utility functions: BuildIMSIdentity, FormatGSMAIMEIURN, etc.
package voiceclient

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/voorz/vowifi-core/engine/sim"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
)

// Config configures IMS SIP signaling. After architecture refactoring,
// this is consumed by imscore.Service (via imscore.ConfigFromVoice) rather
// than by a voiceclient.Client.
type Config struct {
	DeviceID string
	TraceID  string

	// LocalIP is the tunnel's assigned virtual IP (swu.Session.LocalIP());
	// the SIP UA binds here so traffic actually flows through the SWu
	// tunnel rather than the host's default route.
	LocalIP net.IP

	// Dataplane sends and receives inner IP packets through the SWu Child SA.
	// When present, SIP UDP runs fully in-process and does not bind the
	// tunnel IP on the host kernel.
	Dataplane PacketDataplane

	// LocalPort is the port to listen on at LocalIP. 0 defaults to 5060.
	LocalPort int

	// PCSCFAddr is the P-CSCF ("host:port") to REGISTER against and route
	// MESSAGE through. See the package doc comment: required because
	// discovery isn't wired up yet.
	PCSCFAddr string

	// SecurityVerify is the verified Security-Server mechanism from the
	// authenticated REGISTER. Protected non-REGISTER requests must mirror it.
	SecurityVerify string

	// SMSC is the service-centre address used to construct the SC PSI for
	// originating SMS-over-IMS MESSAGE requests.
	SMSC string

	// ServiceRoutes are the raw Service-Route values learned from REGISTER.
	ServiceRoutes []string

	// RegistrarCandidates is the ordered IKE/ePDG P-CSCF list for imscore
	// registrar probing. When empty, imscore falls back to PCSCFAddr.
	RegistrarCandidates []string

	// Transport is the IMS SIP transport for this carrier profile: "udp" or "tcp".
	// When empty, legacy behavior falls back to UDP if Dataplane is present, else TCP.
	Transport string

	// Realm is the IMS realm used in REGISTER/Authorization (e.g.
	// "ims.mnc001.mcc001.3gppnetwork.org").
	Realm string

	// PrivateID is the IMS private identity / IMPI used for digest AKA auth.
	PrivateID string

	// PublicURI is the SIP public identity / IMPU used in From/To/P-Preferred-Identity.
	PublicURI string

	// IMSI is the live SIM IMSI used to build handset-mimic IMS identities.
	IMSI string

	// EAPPrivateID is the SWu tunnel EAP-AKA identity (nai.epc...), kept for
	// REGISTER variants that fall back to the default private-id shape.
	EAPPrivateID string

	// HomeDomain is the registrar/home domain used in the REGISTER Request-URI.
	HomeDomain string

	// AKA computes IMS-AKA (RFC 3310) responses. The same sim.AKAProvider
	// already authenticating the SWu tunnel's EAP-AKA -- a second,
	// independent AKA run against the P-CSCF/S-CSCF's own RAND/AUTN.
	AKA sim.AKAProvider

	DeliveryStore messaging.DeliveryStore

	// RegisterExpiry is the requested REGISTER expiration. <= 0 defaults to
	// 3600s; the re-register interval is half that.
	RegisterExpiry time.Duration

	// MCC/MNC identify the home PLMN for carrier-specific REGISTER headers.
	// When empty, PLMN is derived from HomeDomain.
	MCC string
	MNC string

	// SPN is the SIM EF_SPN service provider name, used for MVNO disambiguation
	// when multiple carrier profiles share the same PLMN.
	SPN string

	// CellID is an optional E-UTRAN cell identity suffix (hex) appended to the
	// home PLMN in Cellular-Network-Info. When empty, SimAdmin-style placeholder
	// zeros are used.
	CellID string

	// RegisterProfile optionally overrides carrier-specific REGISTER headers.
	RegisterProfile RegisterProfile

	// SIPInstanceURN optionally overrides the +sip.instance value (e.g. urn:gsma:imei:...).
	SIPInstanceURN string

	// SkipRegister skips the REGISTER handshake when IMS registration was already
	// completed by imscore (ipsec-3gpp path).
	SkipRegister bool

	// TCPKeepaliveSeconds controls how often to send SIP OPTIONS keepalive on
	// the IMS TCP connection to prevent P-CSCF from closing idle connections.
	// 0 means use the default (15s). Negative disables.
	TCPKeepaliveSeconds int

	// OptionsPingIntervalSeconds controls how often to send SIP OPTIONS
	// ping as a higher-level liveness check. 0 means use the default (30s).
	// Negative disables.
	OptionsPingIntervalSeconds int
}

func (c Config) contactURI() string {
	transport := c.transportNetwork()
	user := c.contactUser()
	if user == "" {
		user = "anonymous"
	}
	return fmt.Sprintf("sip:%s@%s;transport=%s", user, net.JoinHostPort(c.LocalIP.String(), strconv.Itoa(c.localPort())), transport)
}

func (c Config) contactUser() string {
	publicURI := strings.TrimSpace(c.PublicURI)
	if strings.HasPrefix(strings.ToLower(publicURI), "sip:") {
		publicURI = publicURI[4:]
	}
	if idx := strings.Index(publicURI, "@"); idx > 0 {
		return publicURI[:idx]
	}
	return strings.TrimSpace(c.PrivateID)
}

func (c Config) transportNetwork() string {
	switch strings.ToLower(strings.TrimSpace(c.Transport)) {
	case "tcp", "udp":
		return strings.ToLower(strings.TrimSpace(c.Transport))
	default:
		if c.Dataplane != nil {
			return "udp"
		}
		return "tcp"
	}
}

func (c Config) localPort() int {
	if c.LocalPort > 0 {
		return c.LocalPort
	}
	return 5060
}

func (c Config) registerExpiry() time.Duration {
	if c.RegisterExpiry > 0 {
		return c.RegisterExpiry
	}
	return 3600 * time.Second
}

func imsListenAddr(localIP net.IP, port int) string {
	return net.JoinHostPort(localIP.String(), strconv.Itoa(port))
}
