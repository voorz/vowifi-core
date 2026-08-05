//go:build !linux

package runtimehost

import (
	"strings"

	"github.com/voorz/vowifi-core/profiles"
)

func simAdminIMSTransport(mcc, mnc, spn string) string {
	// JSON-first: try embedded profiles before falling back to default.
	if p, err := profiles.LookupWithSPN(mcc, mnc, spn); err == nil && p != nil {
		if tm := strings.TrimSpace(p.IMS.TransportMode); tm != "" {
			return strings.ToLower(tm)
		}
	}
	return "udp"
}
