package voicehost

import "strings"

// isProtectedDialogHeader reports whether the given header name is a
// SIP dialog-level header that must not be overwritten by downstream
// agents (e.g. To, From, Call-ID, Via, Contact …).
//
// Extracted from vowifi-go ims_agent.go during the V0a Gateway port.
// When V2 (IMS Agent) is ported this file may be superseded by the
// full ims_agent.go implementation.
func isProtectedDialogHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "to", "from", "call-id", "cseq", "max-forwards", "route", "record-route", "via", "contact", "content-length", "content-type", "rack", "refer-to", "referred-by", "event", "subscription-state":
		return true
	default:
		return false
	}
}

// firstVoiceNonEmpty returns the first non-blank string from the
// variadic arguments (after trimming whitespace).  Returns "" when
// none of the items contain visible text.
//
// Extracted from vowifi-go ims_agent.go during the V0a Gateway port.
func firstVoiceNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return strings.TrimSpace(item)
		}
	}
	return ""
}
