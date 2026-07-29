//go:build linux

package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/voorz/swu-go/pkg/logger"
	externalsim "github.com/voorz/swu-go/pkg/sim"
	externalswu "github.com/voorz/swu-go/pkg/swu"
	swusim "github.com/voorz/vowifi-core/engine/sim"
)

type externalSIMAdapter struct {
	inner SIMAdapter
}

func (a externalSIMAdapter) GetIMSI() (string, error) {
	if a.inner == nil {
		return "", externalsim.ErrSIMNotPresent
	}
	return a.inner.GetIMSI()
}

func (a externalSIMAdapter) CalculateAKA(randBytes, autnBytes []byte) (res, ck, ik, auts []byte, err error) {
	if a.inner == nil {
		return nil, nil, nil, nil, externalsim.ErrSIMNotPresent
	}
	out, err := a.inner.CalculateAKA(randBytes, autnBytes)
	if err != nil {
		if errors.Is(err, swusim.ErrSyncFailure) {
			return nil, nil, nil, append([]byte(nil), out.AUTS...), externalsim.ErrSyncFailure
		}
		return nil, nil, nil, nil, err
	}
	return append([]byte(nil), out.RES...), append([]byte(nil), out.CK...), append([]byte(nil), out.IK...), nil, nil
}

func (a externalSIMAdapter) Close() error {
	if a.inner == nil {
		return nil
	}
	return a.inner.Close()
}

type swuInnerDataplane interface {
	SendInnerPacket([]byte) error
	InnerPackets() <-chan []byte
}

func (i *Instance) startSWuSession(ctx context.Context, req StartRequest, epdgIP, epdgPort string) (swuSnapshot, net.IP, swuInnerDataplane, func(string, string) error, error) {
	if req.SIM == nil {
		return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: SIM AKA provider unavailable")
	}

	port, err := strconv.Atoi(strings.TrimSpace(epdgPort))
	if err != nil || port <= 0 || port > 65535 {
		return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: invalid ePDG port %q", epdgPort)
	}
	remoteIP := net.ParseIP(epdgIP)
	if remoteIP == nil {
		return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed: invalid ePDG IP %q", epdgIP)
	}

	localIPStr := ""
	usingProxy := req.Proxy != nil && req.Proxy.Enabled && strings.TrimSpace(req.Proxy.Addr) != ""
	// 对齐 v1.5.5 行为：不绑定具体出站 IP，让 OS 自行选择路由
	// 在 mihomo/nikki 透明代理 (fake-ip) 环境下，不绑定可确保代理正确拦截
	_ = remoteIP
	_ = port

	mnc := strings.TrimSpace(req.Profile.MNC)
	if len(mnc) < 3 {
		mnc = strings.Repeat("0", 3-len(mnc)) + mnc
	}

	cfg := &externalswu.Config{
		EpDGAddr:               epdgIP,
		EpDGPort:               uint16(port),
		APN:                    "ims",
		LocalAddr:              localIPStr,
		SIM:                    externalSIMAdapter{inner: req.SIM},
		EnableDriver:           true,
		DataplaneMode:          externalDataplaneMode(req.Dataplane.Mode),
		MCC:                    strings.TrimSpace(req.Profile.MCC),
		MNC:                    mnc,
		IMSI:                   strings.TrimSpace(req.Profile.IMSI),
		LocalPort:              0,
		DisableEAPMACValidation: true,
		DeviceID:               req.DeviceID,
		TraceID:                req.TraceID,
	}
	applySimAdminSWuProfile(cfg, req.Profile.MCC, req.Profile.MNC)
	if factory := buildSWuTransportFactory(req.Proxy); factory != nil {
		cfg.TransportFactory = factory
	}
	if usingProxy {
		logger.Info("VoWiFi SWu 将通过前置代理建立标准 IKE/UDP 隧道",
			logger.String("trace_id", strings.TrimSpace(req.TraceID)),
			logger.String("proxy_id", strings.TrimSpace(req.Proxy.ID)),
			logger.String("proxy_addr", strings.TrimSpace(req.Proxy.Addr)),
			logger.String("epdg_ip", epdgIP),
			logger.Int("epdg_port", port),
			logger.String("udp_ports", "500->4500"))
	}

	const maxSWuRetries = 3
	const swuRetryDelay = 5 * time.Second
	var lastSnap swuSnapshot
	var lastErr error

	for attempt := 0; attempt < maxSWuRetries; attempt++ {
		if attempt > 0 {
			logger.Info("VoWiFi SWu 重试",
				logger.String("trace_id", strings.TrimSpace(req.TraceID)),
				logger.String("epdg_ip", epdgIP),
				logger.Int("attempt", attempt+1),
				logger.Int("max", maxSWuRetries),
				logger.String("delay", swuRetryDelay.String()),
				logger.Err(lastErr))
			select {
			case <-ctx.Done():
				return swuSnapshot{}, nil, nil, nil, fmt.Errorf("%w; last_snapshot=%s", ctx.Err(), formatSWuSnapshot(lastSnap))
			case <-time.After(swuRetryDelay):
			}
		}

		readyCh := make(chan struct{})
		var readyOnce sync.Once
		cfg.OnReady = func() {
			readyOnce.Do(func() { close(readyCh) })
		}

		session := externalswu.NewSession(cfg, logger.Get())
		errCh := make(chan error, 1)
		go func() { errCh <- session.Connect(ctx) }()

		ticker := time.NewTicker(500 * time.Millisecond)
		deadline := time.NewTimer(90 * time.Second)
		sessionDone := false
		var sessionMobike func(string, string) error

		for !sessionDone {
			select {
			case <-ctx.Done():
				ticker.Stop()
				deadline.Stop()
				return swuSnapshot{}, nil, nil, nil, fmt.Errorf("%w; last_snapshot=%s", ctx.Err(), formatSWuSnapshot(lastSnap))
			case err := <-errCh:
				ticker.Stop()
				deadline.Stop()
				lastSnap = fromExternalSnapshot(session.Snapshot())
				lastErr = err
				sessionDone = true
				if err != nil {
					if isDataplanePermissionError(err) {
						return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu userspace dataplane failed: configuring TUN requires root/CAP_NET_ADMIN: %w; last_snapshot=%s", err, formatSWuSnapshot(lastSnap))
					}
					continue
				}
				if !lastSnap.Established || !snapshotHasLocalIP(lastSnap) {
					lastErr = fmt.Errorf("SWu tunnel finished without usable Child SA; last_snapshot=%s", formatSWuSnapshot(lastSnap))
					continue
				}
				sessionMobike = func(oldIP, newIP string) error {
					target := epdgIP
					_ = oldIP
					return session.UpdateAddresses(newIP, target)
				}
				return lastSnap, preferTunnelLocalIP(lastSnap), session, sessionMobike, nil
			case <-readyCh:
				ticker.Stop()
				deadline.Stop()
				lastSnap = fromExternalSnapshot(session.Snapshot())
				sessionDone = true
				if !lastSnap.Established || !snapshotHasLocalIP(lastSnap) {
					lastErr = fmt.Errorf("SWu dataplane reported ready without usable tunnel IP; last_snapshot=%s", formatSWuSnapshot(lastSnap))
					continue
				}
				sessionMobike = func(oldIP, newIP string) error {
					target := epdgIP
					_ = oldIP
					return session.UpdateAddresses(newIP, target)
				}
				return lastSnap, preferTunnelLocalIP(lastSnap), session, sessionMobike, nil
			case <-deadline.C:
				ticker.Stop()
				deadline.Stop()
				lastSnap = fromExternalSnapshot(session.Snapshot())
				lastErr = fmt.Errorf("SWu tunnel timed out waiting for Child SA; last_snapshot=%s", formatSWuSnapshot(lastSnap))
				sessionDone = true
			case <-ticker.C:
				lastSnap = fromExternalSnapshot(session.Snapshot())
			}
		}
	}

	return swuSnapshot{}, nil, nil, nil, fmt.Errorf("SWu tunnel failed after %d attempts: %w; last_snapshot=%s", maxSWuRetries, lastErr, formatSWuSnapshot(lastSnap))
}

func externalDataplaneMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "xfrmi":
		return "xfrmi"
	case "tun":
		return "tun"
	case "userspace", "user", "libipsec", "netstack", "userspace-netstack":
		return "netstack"
	default:
		return "netstack"
	}
}

func fromExternalSnapshot(s externalswu.SessionSnapshot) swuSnapshot {
	return swuSnapshot{
		Established: s.Established,
		TUNName:     s.TUNName,
		IPv4:        append(net.IP(nil), s.IPv4...),
		IPv6:        append(net.IP(nil), s.IPv6...),
		PCSCFv4:     append([]net.IP(nil), s.PCSCFv4...),
		PCSCFv6:     append([]net.IP(nil), s.PCSCFv6...),
	}
}

func snapshotHasPCSCF(s swuSnapshot) bool {
	return len(s.PCSCFv4) > 0 || len(s.PCSCFv6) > 0
}

func isDataplanePermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") &&
		(strings.Contains(msg, "addr add") ||
			strings.Contains(msg, "route add") ||
			strings.Contains(msg, "link set") ||
			strings.Contains(msg, "dev tun") ||
			strings.Contains(msg, "/dev/net/tun") ||
			strings.Contains(msg, "xfrm"))
}

func snapshotHasLocalIP(s swuSnapshot) bool {
	return s.IPv4 != nil || s.IPv6 != nil
}

func formatSWuSnapshot(s swuSnapshot) string {
	return fmt.Sprintf("established=%t tun=%q ipv4=%s ipv6=%s pcscfv4=%s pcscfv6=%s",
		s.Established,
		s.TUNName,
		ipString(s.IPv4),
		ipString(s.IPv6),
		ipListString(s.PCSCFv4),
		ipListString(s.PCSCFv6),
	)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func ipListString(ips []net.IP) string {
	if len(ips) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip != nil {
			parts = append(parts, ip.String())
		}
	}
	return strings.Join(parts, ",")
}

func preferTunnelLocalIP(s swuSnapshot) net.IP {
	if s.IPv4 != nil {
		return s.IPv4
	}
	if s.IPv6 != nil {
		return s.IPv6
	}
	return nil
}

func detectOutboundIPv4(remoteIP net.IP, remotePort int) (net.IP, error) {
	r := &net.UDPAddr{IP: remoteIP, Port: remotePort}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", r.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if v4 := ua.IP.To4(); v4 != nil && !v4.Equal(net.IPv4zero) {
			return v4, nil
		}
	}
	return nil, fmt.Errorf("cannot detect outbound ip")
}
