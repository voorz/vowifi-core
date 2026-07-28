// Package swu tunnel types: supports the TUN dataplane mode where a local
// TUN device carries decrypted tunnel traffic, with routing and EPDG
// exclusions managed by the host process rather than charon's
// kernel-libipsec. These types mirror the interface contract from the
// original vohive-libs-vowifi-go TUN management layer, but are decoupled
// from the standalone IKEv2 implementation—the swu-go/charon session
// adapter provides the PacketTunnelReadSession implementation instead.
package swu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DataplaneModeDisabled = "disabled"

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	ErrInvalidTunnelConfig       = errors.New("invalid swu tunnel config")
	ErrTunnelNotReady            = errors.New("swu tunnel not ready")
	ErrInvalidPacketTunnel       = errors.New("invalid swu packet tunnel")
	ErrPacketTunnelClosed        = errors.New("swu packet tunnel closed")
	ErrUnsupportedInnerPacket    = errors.New("unsupported inner packet")
	ErrInvalidChildSARekeyPolicy = errors.New("invalid swu child sa rekey policy")
)

// ---------------------------------------------------------------------------
// Config & result structs
// ---------------------------------------------------------------------------

type ProxyConfig struct {
	ID       string
	URL      string
	Address  string
	Addr     string
	Username string
	Password string
	Country  string
	Enabled  bool
}

type IMSIdentity struct {
	IMPI   string
	IMPU   string
	Domain string
}

type TunnelConfig struct {
	DeviceID       string
	TraceID        string
	Mode           string
	EPDGAddress    string
	EPDGSource     string
	LocalInterface string
	OuterLocalIP   string
	InnerLocalIP   string
	RemoteInnerIP  string
	IMSI           string
	MCC            string
	MNC            string
	IMEI           string
	Identity       IMSIdentity
	Proxy          *ProxyConfig
	StartedAt      time.Time
}

func (c TunnelConfig) NormalizedMode() string {
	mode := strings.ToLower(strings.TrimSpace(c.Mode))
	if mode == "" {
		return DataplaneModeUserspace
	}
	return mode
}

func (c TunnelConfig) Validate() error {
	if strings.TrimSpace(c.DeviceID) == "" {
		return fmt.Errorf("%w: device_id is empty", ErrInvalidTunnelConfig)
	}
	switch mode := c.NormalizedMode(); mode {
	case DataplaneModeDisabled:
		return nil
	case DataplaneModeUserspace, DataplaneModeKernel, "tun":
	default:
		return fmt.Errorf("%w: unsupported dataplane mode %q", ErrInvalidTunnelConfig, mode)
	}
	if strings.TrimSpace(c.EPDGAddress) == "" && (strings.TrimSpace(c.MCC) == "" || strings.TrimSpace(c.MNC) == "") {
		return fmt.Errorf("%w: ePDG address or MCC/MNC is required", ErrInvalidTunnelConfig)
	}
	if strings.TrimSpace(c.IMSI) == "" && strings.TrimSpace(c.Identity.IMPI) == "" {
		return fmt.Errorf("%w: IMSI or IMPI is required", ErrInvalidTunnelConfig)
	}
	return nil
}

type TunnelResult struct {
	Ready             bool
	Mode              string
	EPDGAddress       string
	LocalInnerIP      string
	RemoteInnerIP     string
	DNSServers        []string
	IKEEstablished    bool
	IPsecEstablished  bool
	MOBIKESupported   bool
	ChildSAIdentifier string
	Reason            string
	EstablishedAt     time.Time
}

func (r TunnelResult) IsReady() bool {
	return r.Ready && r.IKEEstablished && r.IPsecEstablished
}

func cloneTunnelResult(r TunnelResult) TunnelResult {
	r.DNSServers = append([]string(nil), r.DNSServers...)
	return r
}

func isZeroTunnelResult(r TunnelResult) bool {
	return !r.Ready &&
		strings.TrimSpace(r.Mode) == "" &&
		strings.TrimSpace(r.EPDGAddress) == "" &&
		strings.TrimSpace(r.LocalInnerIP) == "" &&
		strings.TrimSpace(r.RemoteInnerIP) == "" &&
		len(r.DNSServers) == 0 &&
		!r.IKEEstablished &&
		!r.IPsecEstablished &&
		!r.MOBIKESupported &&
		strings.TrimSpace(r.ChildSAIdentifier) == "" &&
		strings.TrimSpace(r.Reason) == "" &&
		r.EstablishedAt.IsZero()
}

// ---------------------------------------------------------------------------
// MOBIKE types
// ---------------------------------------------------------------------------

type MOBIKERequest struct {
	DeviceID string
	TraceID  string
	OldIP    string
	NewIP    string
	At       time.Time
}

type MOBIKEResult struct {
	Rekeyed          bool
	OuterLocalIP     string
	LocalInnerIP     string
	RemoteInnerIP    string
	DNSServers       []string
	IKEEstablished   bool
	IPsecEstablished bool
	Reason           string
	UpdatedAt        time.Time
}

// ---------------------------------------------------------------------------
// Child SA rekey types
// ---------------------------------------------------------------------------

type ChildSARekeyAction uint8

const (
	ChildSARekeyNoAction ChildSARekeyAction = iota
	ChildSARekeyDue
)

func (a ChildSARekeyAction) String() string {
	switch a {
	case ChildSARekeyNoAction:
		return "none"
	case ChildSARekeyDue:
		return "rekey"
	default:
		return fmt.Sprintf("child sa rekey action %d", a)
	}
}

type ChildSARekeyPolicy struct {
	Lifetime time.Duration
	LeadTime time.Duration
	Disabled bool
}

type ChildSARekeyDecision struct {
	Action        ChildSARekeyAction
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	NextDue       time.Time
	Age           time.Duration
	TimeToExpire  time.Duration
	Lifetime      time.Duration
	LeadTime      time.Duration
	Expired       bool
	Reason        string
}

type ChildSARekeySnapshot struct {
	Enabled       bool
	EstablishedAt time.Time
	DueAt         time.Time
	ExpiresAt     time.Time
	Lifetime      time.Duration
	LeadTime      time.Duration
}

// ---------------------------------------------------------------------------
// Packet tunnel types
// ---------------------------------------------------------------------------

type PacketTunnelStats struct {
	OutboundInnerPackets uint64
	OutboundInnerBytes   uint64
	OutboundESPPackets   uint64
	OutboundESPBytes     uint64
	OutboundErrors       uint64
	InboundInnerPackets  uint64
	InboundInnerBytes    uint64
	InboundESPPackets    uint64
	InboundESPBytes      uint64
	InboundErrors        uint64
	ReplayDrops          uint64
	InvalidDrops         uint64
	UnsupportedDrops     uint64
}

type PacketTunnelPacket struct {
	SPI        uint32
	Sequence   uint32
	NextHeader uint8
	Payload    []byte
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

type TunnelManager interface {
	EstablishTunnel(context.Context, TunnelConfig) (TunnelSession, error)
}

type TunnelSession interface {
	Result() TunnelResult
	MOBIKE(context.Context, MOBIKERequest) (MOBIKEResult, error)
	Close(context.Context) error
}

type PacketTunnelSession interface {
	TunnelSession
	SendInnerPacket(context.Context, []byte) error
	SendInnerPacketWithNextHeader(context.Context, uint8, []byte) error
	ReceiveESPPacket(context.Context, []byte) (PacketTunnelPacket, error)
	PacketStats() PacketTunnelStats
}

type PacketTunnelReadSession interface {
	PacketTunnelSession
	ReadInnerPacket(context.Context) (PacketTunnelPacket, error)
}

type ChildSARekeyController interface {
	RekeyChildSA(context.Context) (TunnelResult, error)
}

type ChildSARekeyScheduler interface {
	RekeyChildSA(context.Context) (TunnelResult, error)
	NextChildSARekeyDue() (time.Time, bool)
	RunChildSARekeyDue(context.Context, time.Time) (ChildSARekeyDecision, error)
	ChildSARekeySnapshot() ChildSARekeySnapshot
}

type MOBIKENATObserver interface {
	ObserveMOBIKENAT(context.Context, MOBIKENATObservation) (MOBIKENATChange, MOBIKEResult, error)
	MOBIKENATSnapshot() (MOBIKENATEndpoint, time.Time)
}

type IKELivenessController interface {
	AdvanceIKELiveness(context.Context, time.Time) (IKELivenessDecision, error)
	RecordIKELivenessInbound(time.Time)
	RecordIKELivenessOutbound(time.Time)
	RecordIKELivenessResult(time.Time, bool)
	IKELivenessSnapshot() IKELivenessSnapshot
}

// Stub types for MOBIKE NAT and IKE liveness (not used in TUN mode with
// swu-go/charon, but needed for interface compliance).

type MOBIKENATObservation struct{}
type MOBIKENATChange struct {
	RequiresMOBIKEUpdate bool
	Request             MOBIKERequest
}
type MOBIKENATEndpoint struct{}
type IKELivenessDecision struct {
	Action           IKELivenessAction
	Dead             bool
	MissedDPDProbes  int
	Reason           string
}
type IKELivenessSnapshot struct {
	Dead bool
}
type IKELivenessAction uint8

const (
	IKELivenessNoAction IKELivenessAction = iota
	IKELivenessSendKeepalive
	IKELivenessSendDPD
	IKELivenessDeclareDead
)

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func contextReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func firstPacketNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}

func normalizedMOBIKEIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func tunnelAddressHost(addr string) string {
	host := strings.TrimSpace(addr)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
