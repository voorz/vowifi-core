package imscore

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// KernelIMSNetwork routes IMS sockets through the kernel network stack.
// When the SWu dataplane is in "tun" mode, swu-go creates a TUN device
// and configures routing so that traffic bound to the tunnel IP goes
// through that device. SIP/RTP sockets created via standard Go net.Dial /
// net.Listen automatically use the TUN device—no userspace netstack is
// needed.
//
// This implementation satisfies the IMSNetwork interface using only the
// kernel's socket layer, binding to the tunnel local IP.
type KernelIMSNetwork struct {
	localIP net.IP
}

var _ IMSNetwork = (*KernelIMSNetwork)(nil)

// NewKernelIMSNetwork builds an IMSNetwork backed by kernel sockets.
// localIP is the inner tunnel address assigned by the ePDG (the address
// swu-go configured on the TUN device).
func NewKernelIMSNetwork(localIP net.IP) (*KernelIMSNetwork, error) {
	if localIP == nil {
		return nil, fmt.Errorf("imscore: local IP is required")
	}
	return &KernelIMSNetwork{localIP: localIP}, nil
}

func (n *KernelIMSNetwork) DialContext(ctx context.Context, network string, addr net.Addr, transport string, opts DialOptions) (net.Conn, error) {
	if n == nil || n.localIP == nil {
		return nil, fmt.Errorf("imscore: kernel IMS network unavailable")
	}
	localPort := 5060
	if l, ok := ctx.Value(localPortContextKey{}).(int); ok && l > 0 {
		localPort = l
	}
	if network == "udp" || transport == "udp" {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || udpAddr == nil {
			return nil, fmt.Errorf("imscore: invalid UDP addr %v", addr)
		}
		dialer := &net.Dialer{}
		if localPort > 0 {
			dialer.LocalAddr = &net.UDPAddr{IP: n.localIP, Port: localPort}
		}
		return dialer.DialContext(ctx, "udp", net.JoinHostPort(udpAddr.IP.String(), strconv.Itoa(udpAddr.Port)))
	}
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return nil, fmt.Errorf("imscore: invalid TCP addr %v", addr)
	}
	dialer := &net.Dialer{}
	if localPort > 0 {
		dialer.LocalAddr = &net.TCPAddr{IP: n.localIP, Port: localPort}
	}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(tcpAddr.Port)))
}

func (n *KernelIMSNetwork) HasLocalIP(ip []byte) bool {
	if n == nil || n.localIP == nil || len(ip) == 0 {
		return false
	}
	return n.localIP.Equal(net.IP(ip))
}

func (n *KernelIMSNetwork) ListenPacket(ctx context.Context, network string, addr net.Addr) (net.PacketConn, error) {
	if n == nil || n.localIP == nil {
		return nil, fmt.Errorf("imscore: kernel IMS network unavailable")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return nil, fmt.Errorf("imscore: invalid UDP listen addr %v", addr)
	}
	port := udpAddr.Port
	if port <= 0 {
		port = 5060
	}
	lc := &net.ListenConfig{}
	return lc.ListenPacket(ctx, "udp", net.JoinHostPort(n.localIP.String(), strconv.Itoa(port)))
}

func (n *KernelIMSNetwork) ListenTCP(ctx context.Context, laddr *net.TCPAddr) (net.Listener, error) {
	if n == nil || n.localIP == nil {
		return nil, fmt.Errorf("imscore: kernel IMS network unavailable")
	}
	if laddr == nil {
		return nil, fmt.Errorf("imscore: listen addr is required")
	}
	port := laddr.Port
	if port <= 0 {
		port = 5060
	}
	lc := &net.ListenConfig{}
	return lc.Listen(ctx, "tcp", net.JoinHostPort(n.localIP.String(), strconv.Itoa(port)))
}

func (n *KernelIMSNetwork) LocalIP() []byte {
	if n == nil || n.localIP == nil {
		return nil
	}
	return append([]byte(nil), n.localIP...)
}

func (n *KernelIMSNetwork) ResolveIP(ctx context.Context, host string, preferIPv6 bool) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("imscore: resolve %q: %w", host, err)
	}
	if preferIPv6 {
		for _, ip := range ips {
			if ip.To4() == nil {
				return ip, nil
			}
		}
	}
	return ips[0], nil
}

func (n *KernelIMSNetwork) SWUDialer() voiceclient.SWUTCPDialer {
	// KernelIMSNetwork does not provide a userspace SWU dialer.
	// SIP transport uses kernel sockets directly via DialContext.
	return nil
}

func (n *KernelIMSNetwork) Close() error {
	// Nothing to close—kernel sockets are managed by their callers.
	return nil
}
