package voiceclient

import "strings"

// NormalizeUserAgent strips a leading "User-Agent:" prefix from the value if
// present. Carrier profile JSON files and hardcoded fallbacks sometimes store
// the full header line (e.g. "User-Agent: Apple iPhone...") rather than just
// the value. When the caller does sip.NewHeader("User-Agent", ua), the prefix
// would be duplicated, producing "User-Agent: User-Agent: Apple iPhone...".
//
// This function ensures the value is always just the bare UA string, regardless
// of how it was configured.
func NormalizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	// Strip a leading "User-Agent:" (case-insensitive) if the config
	// author accidentally included the header name in the value.
	if len(ua) > len("User-Agent:") && strings.EqualFold(ua[:len("User-Agent:")], "User-Agent:") {
		ua = strings.TrimSpace(ua[len("User-Agent:"):])
	}
	return ua
}
