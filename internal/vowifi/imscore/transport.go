package imscore

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/vowifi-core/internal/vowifi/ipsec3gpp"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

func newSWUNetstack(localIP net.IP, dp voiceclient.PacketDataplane, traceID, deviceID string) (voiceclient.SWUTCPDialer, error) {
	if dp == nil {
		return nil, nil
	}
	return voiceclient.NewSWUTCPDialer(localIP, dp, traceID, deviceID)
}

func dialPlainTCP(ctx context.Context, cfg Config, swu voiceclient.SWUTCPDialer) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(cfg.PCSCFAddr)
	if err != nil {
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	rip := net.ParseIP(host)
	if rip == nil {
		return nil, fmt.Errorf("imscore: invalid P-CSCF %q", cfg.PCSCFAddr)
	}
	if swu != nil {
		return swu.DialContextTCP(ctx, cfg.LocalIP, 5060, rip, port)
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: cfg.LocalIP, Port: 5060}}
	return d.DialContext(ctx, "tcp", cfg.PCSCFAddr)
}

type fixedConnDialer struct {
	mu   sync.Mutex
	conn net.Conn
}

func (d *fixedConnDialer) set(conn net.Conn) {
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
}

func (d *fixedConnDialer) dial(ctx context.Context, laddr net.Addr, raddr net.Addr) (net.Conn, error) {
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	if conn == nil {
		return nil, fmt.Errorf("imscore: SIP connection not ready")
	}
	return conn, nil
}

func newRegisterSIPStack(cfg Config, conn net.Conn, swu voiceclient.SWUTCPDialer, localPort int) (*sipgo.UserAgent, *sipgo.Client, error) {
	if localPort <= 0 {
		localPort = 5060
	}
	var dialer *fixedConnDialer
	if conn != nil {
		dialer = &fixedConnDialer{}
		dialer.set(conn)
	}
	return newSIPStack(cfg, dialer, swu, localPort)
}

func newSecureRegisterSIPStack(cfg Config, conn *ipsec3gpp.SecureChannelConn) (*sipgo.UserAgent, *sipgo.Client, error) {
	localPort := 5060
	if conn != nil && conn.LocalAddr() != nil {
		if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok && ta.Port > 0 {
			localPort = ta.Port
		}
	}
	var dialer *fixedConnDialer
	if conn != nil {
		dialer = &fixedConnDialer{}
		dialer.set(conn)
	}
	return newSIPStack(cfg, dialer, nil, localPort)
}

func newSIPStack(cfg Config, dialer *fixedConnDialer, swu voiceclient.SWUTCPDialer, localPort int) (*sipgo.UserAgent, *sipgo.Client, error) {
	installSIPTrace(cfg.TraceID, cfg.DeviceID)
	deviceLogger := slog.New(logger.NewSlogHandler(logger.Get())).With(
		"device_id", strings.TrimSpace(cfg.DeviceID),
		"trace_id", strings.TrimSpace(cfg.TraceID),
	)
	tpOpts := []sip.TransportLayerOption{
		sip.WithTransportLayerLogger(deviceLogger),
		sip.WithTransportLayerTransports(sip.TransportsConfig{
			TCP: &sip.TransportTCP{
				DialContext: func(ctx context.Context, laddr net.Addr, raddr net.Addr) (net.Conn, error) {
					if dialer != nil {
						return dialer.dial(ctx, laddr, raddr)
					}
					if swu != nil {
						tcpAddr, ok := raddr.(*net.TCPAddr)
						if !ok || tcpAddr == nil {
							return nil, fmt.Errorf("imscore: invalid TCP remote addr %v", raddr)
						}
						port := localPort
						if localTCP, ok := laddr.(*net.TCPAddr); ok && localTCP != nil && localTCP.Port > 0 {
							port = localTCP.Port
						}
						transportAddr := effectiveTransportAddr(cfg)
						transportHost, transportPortStr, err := net.SplitHostPort(transportAddr)
						if err != nil {
							return nil, err
						}
						transportPort, err := strconv.Atoi(transportPortStr)
						if err != nil {
							return nil, err
						}
						transportIP := net.ParseIP(transportHost)
						if transportIP == nil {
							return nil, fmt.Errorf("imscore: invalid transport P-CSCF %q", transportAddr)
						}
						return swu.DialContextTCP(ctx, cfg.LocalIP, port, transportIP, transportPort)
					}
					return net.DialTimeout("tcp", raddr.String(), registerTransactionTimeout)
				},
			},
		}),
	}
	uaOpts := []sipgo.UserAgentOption{
		sipgo.WithUserAgent(cfg.UserAgent),
		sipgo.WithUserAgentTransportLayerOptions(tpOpts...),
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerLogger(deviceLogger),
		),
	}
	ua, err := sipgo.NewUA(uaOpts...)
	if err != nil {
		return nil, nil, err
	}
	client, err := sipgo.NewClient(ua,
		sipgo.WithClientHostname(cfg.LocalIP.String()),
		sipgo.WithClientPort(localPort),
		sipgo.WithClientConnectionAddr(net.JoinHostPort(cfg.LocalIP.String(), fmt.Sprintf("%d", localPort))),
	)
	if err != nil {
		_ = ua.Close()
		return nil, nil, err
	}
	return ua, client, nil
}
