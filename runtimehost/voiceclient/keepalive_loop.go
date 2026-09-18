package voiceclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

// defaultTCPKeepaliveInterval is the default interval for SIP OPTIONS
// keepalive on the IMS TCP connection when TCPKeepaliveSeconds is 0
// (unset). This prevents P-CSCF from closing idle TCP connections.
const defaultTCPKeepaliveInterval = 15 * time.Second

// defaultOptionsPingInterval is the default interval for SIP OPTIONS
// liveness probing when OptionsPingIntervalSeconds is 0 (unset).
// This is complementary to TCPKeepaliveSeconds — a higher-level check
// that the P-CSCF is still responsive, not just that the TCP socket
// is open.
const defaultOptionsPingInterval = 30 * time.Second

// keepaliveTransactionTimeout is the max time to wait for an OPTIONS
// response before giving up and logging a warning.
const keepaliveTransactionTimeout = 10 * time.Second

// startKeepaliveLoop starts a background SIP OPTIONS keepalive loop on
// the IMS TCP connection. This prevents the P-CSCF from closing the
// connection due to inactivity between REGISTER refreshes.
//
// The loop sends a minimal SIP OPTIONS request to the P-CSCF at the
// configured interval. If TCPKeepaliveSeconds is 0, the default (15s)
// is used. If negative, keepalive is disabled.
//
// This is called by AttachSecureMessaging after the unified SIP stack
// is established, complementing the REGISTER refresh loop (which runs
// at expires * 80% — typically 32 minutes — far too long for NAT/P-CSCF
// idle timeouts).
func (c *Client) startKeepaliveLoop(tcpKeepaliveSecs, optionsPingSecs int) {
	// Resolve TCP keepalive interval.
	tcpInterval := defaultTCPKeepaliveInterval
	if tcpKeepaliveSecs > 0 {
		tcpInterval = time.Duration(tcpKeepaliveSecs) * time.Second
	} else if tcpKeepaliveSecs < 0 {
		// Negative = explicitly disabled.
		tcpInterval = 0
	}

	// Resolve OPTIONS ping interval.
	pingInterval := defaultOptionsPingInterval
	if optionsPingSecs > 0 {
		pingInterval = time.Duration(optionsPingSecs) * time.Second
	} else if optionsPingSecs < 0 {
		pingInterval = 0
	}

	// If both are disabled, skip.
	if tcpInterval <= 0 && pingInterval <= 0 {
		logger.Info(fmt.Sprintf("[%s] IMS keepalive 已禁用", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)))
		return
	}

	// Use the shorter of the two intervals as the tick interval.
	// On each tick, send OPTIONS if both intervals have elapsed.
	// In practice, tcpInterval (15s) is shorter than pingInterval (30s),
	// so every other tick is also an OPTIONS ping tick.
	tickInterval := tcpInterval
	if pingInterval > 0 && (tickInterval <= 0 || pingInterval < tickInterval) {
		tickInterval = pingInterval
	}

	logger.Info(fmt.Sprintf("[%s] IMS keepalive 循环已启动", strings.TrimSpace(c.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
		logger.String("tcp_keepalive", tcpInterval.String()),
		logger.String("options_ping", pingInterval.String()))

	go func() {
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()

		lastTCPKeepalive := time.Now()
		lastOptionsPing := time.Now()

		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				now := time.Now()

				// TCP keepalive: send OPTIONS to keep the TCP connection alive.
				if tcpInterval > 0 && now.Sub(lastTCPKeepalive) >= tcpInterval {
					c.sendKeepaliveOPTIONS(now, "tcp_keepalive")
					lastTCPKeepalive = now
				}

				// OPTIONS ping: higher-level liveness check.
				if pingInterval > 0 && now.Sub(lastOptionsPing) >= pingInterval {
					c.sendKeepaliveOPTIONS(now, "options_ping")
					lastOptionsPing = now
				}
			}
		}
	}()
}

// sendKeepaliveOPTIONS sends a minimal SIP OPTIONS request to the P-CSCF
// to keep the TCP connection alive and probe P-CSCF liveness.
func (c *Client) sendKeepaliveOPTIONS(now time.Time, reason string) {
	if c.client == nil {
		return
	}

	// Build a minimal OPTIONS request.
	// Target: P-CSCF address (the SIP server we're connected to).
	target := strings.TrimSpace(c.cfg.PCSCFAddr)
	if target == "" {
		// Fall back to home domain if P-CSCF addr is not set.
		target = strings.TrimSpace(c.cfg.HomeDomain)
	}
	if target == "" {
		return
	}

	req, err := c.newRequest(sip.OPTIONS, target, false)
	if err != nil {
		logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 构建失败", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("reason", reason),
			logger.String("error", err.Error()))
		return
	}

	// Send the OPTIONS request with a short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), keepaliveTransactionTimeout)
	defer cancel()

	tx, err := c.client.TransactionRequest(ctx, req)
	if err != nil {
		logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 发送失败", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("reason", reason),
			logger.String("error", err.Error()))
		return
	}
	defer tx.Terminate()

	select {
	case <-tx.Done():
		// Transaction completed (response received or timed out at SIP layer).
		if err := tx.Err(); err != nil {
			logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 事务异常", strings.TrimSpace(c.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
				logger.String("reason", reason),
				logger.String("error", err.Error()))
		}
	case res := <-tx.Responses():
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 响应异常", strings.TrimSpace(c.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
				logger.String("reason", reason),
				logger.Int("sip_code", res.StatusCode),
				logger.String("reason_text", res.Reason))
		}
		// 200/200 OK or any response means the P-CSCF is alive and the TCP
		// connection is still open — that's all we need.
	case <-ctx.Done():
		// Timeout — the P-CSCF didn't respond within the keepalive timeout.
		// This is not fatal; the next tick will retry. If the TCP connection
		// is actually down, the OnConnClose callback will trigger pipeline
		// recovery.
		logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 超时", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("reason", reason))
	}
}
