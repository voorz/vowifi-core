package voiceclient

import (
	"fmt"
	"os"
	"strings"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

type sipTraceLogger struct {
	traceID  string
	deviceID string
}

func (s sipTraceLogger) SIPTraceRead(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info(fmt.Sprintf("[%s] IMS SIP 读取", strings.TrimSpace(s.deviceID)),
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.Int("sip_bytes", len(sipmsg)))
}

func (s sipTraceLogger) SIPTraceWrite(transport string, laddr string, raddr string, sipmsg []byte) {
	logger.Info(fmt.Sprintf("[%s] IMS SIP 写入", strings.TrimSpace(s.deviceID)),
		logger.String("trace_id", strings.TrimSpace(s.traceID)),
		logger.String("device_id", strings.TrimSpace(s.deviceID)),
		logger.String("transport", strings.ToLower(strings.TrimSpace(transport))),
		logger.String("local_addr", laddr),
		logger.String("remote_addr", raddr),
		logger.Int("sip_bytes", len(sipmsg)))
}

func installSIPTrace(traceID, deviceID string) {
	// SIPDebug is process-global; only enable for single-session capture/debug.
	if strings.TrimSpace(os.Getenv("VOHIVE_SIP_TRACE")) == "" {
		return
	}
	sip.SIPDebug = true
	sip.SIPDebugTracer(sipTraceLogger{
		traceID:  traceID,
		deviceID: deviceID,
	})
}
