package imscore

import (
	"net"

	"github.com/voorz/sipgo"
)

// SIPClient returns the imscore-owned sipgo.Client.
// After architecture refactoring, imscore directly holds the SIP client
// instead of delegating to voiceclient.Client.
func (s *Service) SIPClient() *sipgo.Client {
	if s == nil {
		return nil
	}
	return s.sipClient
}

// SIPUA returns the imscore-owned sipgo.UserAgent.
func (s *Service) SIPUA() *sipgo.UserAgent {
	if s == nil {
		return nil
	}
	return s.sipUA
}

// SIPServer returns the imscore-owned sipgo.Server.
func (s *Service) SIPServer() *sipgo.Server {
	if s == nil {
		return nil
	}
	return s.sipServer
}

// PrivateID returns the IMS private identity (IMPI).
func (s *Service) PrivateID() string {
	if s == nil {
		return ""
	}
	return s.basePrivateID
}

// PublicURI returns the IMS public identity (IMPU).
func (s *Service) PublicURI() string {
	if s == nil {
		return ""
	}
	return s.basePublicURI
}

// HomeDomain returns the IMS home domain.
func (s *Service) HomeDomain() string {
	if s == nil {
		return ""
	}
	return s.cfg.HomeDomain
}

// LocalIP returns the local IP address used for IMS signaling.
func (s *Service) LocalIP() net.IP {
	if s == nil {
		return nil
	}
	return s.cfg.LocalIP
}

// LocalPort returns the local port used for IMS signaling.
func (s *Service) LocalPort() int {
	if s == nil {
		return 0
	}
	if s.imsCfg.LocalPort > 0 {
		return s.imsCfg.LocalPort
	}
	return 5060
}

// ContactUser returns the contact user for SIP Contact header.
func (s *Service) ContactUser() string {
	if s == nil {
		return ""
	}
	if s.contactUser != "" {
		return s.contactUser
	}
	return s.contactUserFromURI()
}

// ServiceRoutes returns the Service-Route headers learned from REGISTER.
func (s *Service) ServiceRoutes() []string {
	if s == nil {
		return nil
	}
	return s.serviceRoutes
}
