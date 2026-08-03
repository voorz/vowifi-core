//go:build !linux

package runtimehost

import (
	"strings"

	"github.com/voorz/vowifi-core/profiles"
)

func simAdminIMSTransport(mcc, mnc string) string {
	// JSON-first: try embedded profiles before falling back to default.
	if p, err := profiles.Lookup(mcc, mnc); err == nil && p != nil {
		if tm := strings.TrimSpace(p.IMS.TransportMode); tm != "" {
			return strings.ToLower(tm)
		}
	}
	return "udp"
}
