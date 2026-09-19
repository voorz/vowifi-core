package imscore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

// defaultTCPKeepaliveInterval is the default interval for SIP OPTIONS
// keepalive on the IMS TCP connection when TCPKeepaliveSeconds is 0.
const defaultTCPKeepaliveInterval = 15 * time.Second

// defaultOptionsPingInterval is the default interval for SIP OPTIONS
// liveness probing when OptionsPingIntervalSeconds is 0.
const defaultOptionsPingInterval = 30 * time.Second

// keepaliveTransactionTimeout is the max time to wait for an OPTIONS
// response before giving up and logging a warning.
const keepaliveTransactionTimeout = 10 * time.Second

// startKeepaliveLoop starts a background SIP OPTIONS keepalive loop on
// the IMS TCP connection. This prevents the P-CSCF from closing the
// connection due to inactivity between REGISTER refreshes.
//
// This is the imscore-owned version of voiceclient.Client.startKeepaliveLoop,
// moved here as part of the architecture refactoring.
func (s *Service) startKeepaliveLoop(tcpKeepaliveSecs, optionsPingSecs int) {
	// Resolve TCP keepalive interval.
	tcpInterval := defaultTCPKeepaliveInterval
	if tcpKeepaliveSecs > 0 {
		tcpInterval = time.Duration(tcpKeepaliveSecs) * time.Second
	} else if tcpKeepaliveSecs < 0 {
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
		logger.Info(fmt.Sprintf("[%s] IMS keepalive 已禁用", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)))
		return
	}

	// Use the shorter of the two intervals as the tick interval.
	tickInterval := tcpInterval
	if pingInterval > 0 && (tickInterval <= 0 || pingInterval < tickInterval) {
		tickInterval = pingInterval
	}

	logger.Info(fmt.Sprintf("[%s] IMS keepalive 循环已启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("tcp_keepalive", tcpInterval.String()),
		logger.String("options_ping", pingInterval.String()))

	go func() {
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()

		lastTCPKeepalive := time.Now()
		lastOptionsPing := time.Now()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				now := time.Now()

				if tcpInterval > 0 && now.Sub(lastTCPKeepalive) >= tcpInterval {
					s.sendKeepaliveOPTIONS(now, "tcp_keepalive")
					lastTCPKeepalive = now
				}

				if pingInterval > 0 && now.Sub(lastOptionsPing) >= pingInterval {
					s.sendKeepaliveOPTIONS(now, "options_ping")
					lastOptionsPing = now
				}
			}
		}
	}()
}

// sendKeepaliveOPTIONS sends a minimal SIP OPTIONS request to the P-CSCF
// to keep the TCP connection alive and probe P-CSCF liveness.
func (s *Service) sendKeepaliveOPTIONS(now time.Time, reason string) {
	if s.sipClient == nil {
		return
	}

	target := strings.TrimSpace(s.cfg.PCSCFAddr)
	if target == "" {
		target = strings.TrimSpace(s.cfg.HomeDomain)
	}
	if target == "" {
		return
	}

	req, err := s.newRequest(sip.OPTIONS, target, false)
	if err != nil {
		logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 构建失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("reason", reason),
			logger.String("error", err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), keepaliveTransactionTimeout)
	defer cancel()

	tx, err := s.sipClient.TransactionRequest(ctx, req)
	if err != nil {
		logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 发送失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("reason", reason),
			logger.String("error", err.Error()))
		return
	}
	defer tx.Terminate()

	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 事务异常", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("reason", reason),
				logger.String("error", err.Error()))
		}
	case res := <-tx.Responses():
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 响应异常", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("reason", reason),
				logger.Int("sip_code", res.StatusCode),
				logger.String("reason_text", res.Reason))
		}
	case <-ctx.Done():
		logger.Debug(fmt.Sprintf("[%s] IMS keepalive OPTIONS 超时", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("reason", reason))
	}
}
