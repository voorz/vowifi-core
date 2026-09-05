package imscore

import (
	"encoding/base64"
	"strings"

	"github.com/icholy/digest"
	"github.com/voorz/swu-go/pkg/logger"
)

// buildEAPDirectAuthorization constructs a Digest AKAv1-MD5 Authorization
// header by directly reusing the RES/CK/IK already computed during the
// SWu EAP-AKA exchange — without re-running USIM AKA. This avoids the
// SQN sync failure that occurs when the USIM's SQN has already been
// consumed by the EAP exchange.
//
// The nonce is constructed from EAP RAND||AUTN, and the digest password
// uses the cached EAP RES directly.
//
// Returns empty string if EAPRES/EAPRand/EAPAutn are not available.
func buildEAPDirectAuthorization(cfg Config) string {
	if len(cfg.EAPRES) == 0 || len(cfg.EAPRand) < 16 || len(cfg.EAPAutn) < 16 {
		return ""
	}

	nonce := base64.StdEncoding.EncodeToString(append(
		append([]byte(nil), cfg.EAPRand[:16]...),
		cfg.EAPAutn[:16]...,
	))

	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		realm = strings.TrimSpace(cfg.HomeDomain)
	}

	chal := &digest.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: "AKAv1-MD5",
	}

	opts := digest.Options{
		Method:   "REGISTER",
		URI:      "sip:" + strings.TrimSpace(cfg.HomeDomain),
		Username: authorizationUsername(cfg),
		Password: string(cfg.EAPRES), // 直接复用 EAP 的 RES 作为密码
	}

	// Use the plain digest computation (no USIM AKA needed).
	// Force algorithm to MD5 for computation, then restore wire label.
	mathChal := *chal
	mathChal.Algorithm = "MD5"
	cred, err := digest.Digest(&mathChal, opts)
	if err != nil {
		logger.Warn("imscore: eap_direct Authorization 构建失败",
			logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
			logger.String("error", err.Error()))
		return ""
	}
	cred.Algorithm = "AKAv1-MD5"

	logger.Info("imscore: eap_direct Authorization 构建成功",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.Int("res_len", len(cfg.EAPRES)),
		logger.Int("ck_len", len(cfg.EAPCK)),
		logger.Int("ik_len", len(cfg.EAPIK)))

	return cred.String()
}

// isEAPDirectMode reports whether the variant uses eap_direct (reusing EAP RES).
func isEAPDirectMode(variant initialRegisterVariant) bool {
	return variant.initialAuth == "eap_direct"
}

// resolvePrecalculatedAuth returns the Authorization header for the
// eap_direct mode, or falls back to buildInitialAuthorization for other modes.
func resolvePrecalculatedAuth(cfg Config, variant initialRegisterVariant) string {
	if isEAPDirectMode(variant) {
		return buildEAPDirectAuthorization(cfg)
	}
	return buildInitialAuthorization(cfg, variant.initialAuth)
}

// initialRegisterVariantsPrecalc wraps initialRegisterVariantsBase to
// handle the eap_direct mode.
//
// When the carrier profile configures initial_authorization="eap_direct"
// and EAPRES is available, it returns the eap_direct variant followed by
// standard variants as fallback. This mode reuses EAP RES directly,
// avoiding USIM SQN sync issues.
func initialRegisterVariantsPrecalc(cfg Config) []initialRegisterVariant {
	base := initialRegisterVariantsBase(cfg)
	configuredAuth := strings.TrimSpace(cfg.Template.InitialAuthorization)
	hasEAPRES := len(cfg.EAPRES) > 0

	if configuredAuth == "eap_direct" && hasEAPRES {
		// Config requests eap_direct and we have the EAP RES.
		// Return eap_direct variant first, then standard variants as fallback.
		eapDirect := initialRegisterVariant{
			name:            "eap_direct",
			initialAuth:     "eap_direct",
			includePANI:     templateIncludesPANI(cfg.Template),
			includeCellular: true,
		}
		return append([]initialRegisterVariant{eapDirect}, base...)
	}

	if configuredAuth == "eap_direct" && !hasEAPRES {
		// Config requests eap_direct but EAP RES is unavailable —
		// fall through to standard variants.
		return base
	}

	return base
}
