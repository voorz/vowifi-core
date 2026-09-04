package imscore

import (
	"encoding/base64"
	"strings"

	"github.com/icholy/digest"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/vowifi-core/runtimehost/simauth"
)

// buildPrecalculatedAKAAuthorization constructs a full Digest AKAv1-MD5
// Authorization header using the RAND/AUTN saved from the SWu EAP-AKA
// exchange. This allows the initial REGISTER to carry a valid AKA response
// without first receiving a 401/423 challenge — needed for carriers (e.g.
// 3HK) whose P-CSCF rejects empty-response REGISTER with 403 Forbidden.
//
// Returns empty string if EAPRand/EAPAutn are not available.
func buildPrecalculatedAKAAuthorization(cfg Config) string {
	if len(cfg.EAPRand) < 16 || len(cfg.EAPAutn) < 16 || cfg.AKA == nil {
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
	}

	result, err := simauth.ComputeDigest(cfg.AKA, chal, opts)
	if err != nil {
		logger.Warn("imscore: 预计算 AKA 失败",
			logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
			logger.String("error", err.Error()))
		return ""
	}

	logger.Info("imscore: 预计算 AKA Authorization 构建成功",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.Bool("sync_failure", result.SyncFailure))

	return result.Header
}

// isPrecalculatedMode reports whether the variant uses precalculated AKA.
func isPrecalculatedMode(variant initialRegisterVariant) bool {
	return variant.initialAuth == "aka_precalculated"
}

// resolvePrecalculatedAuth returns the Authorization header for the
// aka_precalculated mode, or falls back to buildInitialAuthorization for
// other modes.
func resolvePrecalculatedAuth(cfg Config, variant initialRegisterVariant) string {
	if isPrecalculatedMode(variant) {
		return buildPrecalculatedAKAAuthorization(cfg)
	}
	return buildInitialAuthorization(cfg, variant.initialAuth)
}

// initialRegisterVariantsPrecalc wraps initialRegisterVariantsBase to
// handle the aka_precalculated mode. When the carrier profile configures
// initial_authorization="aka_precalculated" and EAPRand/EAPAutn are
// available, it returns ONLY the precalculated variant (skipping the
// reject-fallback variant loop). When the config is aka_precalculated but
// EAPRand/EAPAutn are missing, it falls back to the standard variants.
// When EAPRand/EAPAutn are available but the config does not request
// precalc, it prepends the precalc variant as an additional attempt.
func initialRegisterVariantsPrecalc(cfg Config) []initialRegisterVariant {
	base := initialRegisterVariantsBase(cfg)
	configuredAuth := strings.TrimSpace(cfg.Template.InitialAuthorization)
	hasEAPVec := len(cfg.EAPRand) >= 16 && len(cfg.EAPAutn) >= 16

	if configuredAuth == "aka_precalculated" && hasEAPVec {
		// Config explicitly requests precalc and we have the vectors —
		// return ONLY the precalculated variant, skipping the fallback loop.
		return []initialRegisterVariant{{
			name:            "aka_precalculated",
			initialAuth:     "aka_precalculated",
			includePANI:     templateIncludesPANI(cfg.Template),
			includeCellular: true,
		}}
	}

	if configuredAuth == "aka_precalculated" && !hasEAPVec {
		// Config requests precalc but vectors are unavailable —
		// fall through to standard variants.
		return base
	}

	// Auto-detect: if EAP vectors are available, prepend precalc variant.
	if hasEAPVec {
		precalc := initialRegisterVariant{
			name:            "aka_precalculated",
			initialAuth:     "aka_precalculated",
			includePANI:     true,
			includeCellular: true,
		}
		return append([]initialRegisterVariant{precalc}, base...)
	}

	return base
}


