package imscore

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/icholy/digest"

	"github.com/voorz/vowifi-core/engine/sim"
	"github.com/voorz/vowifi-core/internal/vowifi/policy"
)

// TestComputeAKAAuth_PlainMD5_EmptyPassword verifies backward-compatible
// behavior when DigestPassword is not set: the code uses an empty password
// to compute the digest (same as before the fix).
func TestComputeAKAAuth_PlainMD5_EmptyPassword(t *testing.T) {
	home := "ims.mnc033.mcc234.3gppnetwork.org"
	cfg := Config{
		HomeDomain: home,
		Realm:      home,
		PrivateID:  "subscriber@ims.mnc033.mcc234.3gppnetwork.org",
		PublicURI:  "sip:subscriber@ims.mnc033.mcc234.3gppnetwork.org",
		LocalIP:    net.ParseIP("10.0.0.2"),
		PCSCFAddr:  "10.0.0.3:5060",
		Template:   policy.GenericTemplate(),
		AKA: fixedAKA{
			res: bytesRepeat(0x11, 8),
			ck:  bytesRepeat(0x22, 16),
			ik:  bytesRepeat(0x33, 16),
		},
		// DigestPassword intentionally left empty
	}

	shortNonce := base64.StdEncoding.EncodeToString([]byte("shortnonce123456"))
	chal := &digest.Challenge{
		Realm:     home,
		Nonce:     shortNonce,
		Algorithm: "MD5",
		QOP:       []string{"auth"},
	}

	req, err := buildRegisterRequest(cfg, registerState{
		spiC:  10,
		spiS:  11,
		portC: 5062,
		portS: 5063,
	}, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}

	akaResult, authHeader, syncFailure, err := computeAKAAuth(cfg, chal, req)
	if err != nil {
		t.Fatalf("computeAKAAuth: %v", err)
	}

	if len(akaResult.CK) != 0 || len(akaResult.IK) != 0 {
		t.Errorf("expected empty CK/IK for plain MD5, got CK=%d IK=%d",
			len(akaResult.CK), len(akaResult.IK))
	}
	if syncFailure {
		t.Error("expected no sync failure for plain MD5")
	}
	if !strings.Contains(authHeader, "algorithm=MD5") {
		t.Errorf("Authorization = %q, want algorithm=MD5", authHeader)
	}
}

// TestComputeAKAAuth_PlainMD5_WithDigestPassword verifies that when
// DigestPassword is set on the Config (sourced from carrier profile),
// the MD5 digest response is computed using that password — not empty.
// This is the core fix for CMLink UK (234-33) 401 failures.
func TestComputeAKAAuth_PlainMD5_WithDigestPassword(t *testing.T) {
	home := "ims.mnc033.mcc234.3gppnetwork.org"
	cfg := Config{
		HomeDomain:     home,
		Realm:          home,
		PrivateID:      "subscriber@ims.mnc033.mcc234.3gppnetwork.org",
		PublicURI:      "sip:subscriber@ims.mnc033.mcc234.3gppnetwork.org",
		LocalIP:        net.ParseIP("10.0.0.2"),
		PCSCFAddr:      "10.0.0.3:5060",
		Template:       policy.GenericTemplate(),
		DigestPassword: "test_secret_123",
		AKA: fixedAKA{
			res: bytesRepeat(0x11, 8),
			ck:  bytesRepeat(0x22, 16),
			ik:  bytesRepeat(0x33, 16),
		},
	}

	shortNonce := base64.StdEncoding.EncodeToString([]byte("shortnonce123456"))
	chal := &digest.Challenge{
		Realm:     home,
		Nonce:     shortNonce,
		Algorithm: "MD5",
		QOP:       []string{"auth"},
	}

	req, err := buildRegisterRequest(cfg, registerState{
		spiC:  10,
		spiS:  11,
		portC: 5062,
		portS: 5063,
	}, true, initialRegisterVariants(cfg)[0])
	if err != nil {
		t.Fatalf("buildRegisterRequest: %v", err)
	}

	_, authHeaderWithPwd, _, err := computeAKAAuth(cfg, chal, req)
	if err != nil {
		t.Fatalf("computeAKAAuth with password: %v", err)
	}

	// Also compute without password for comparison
	cfgNoPwd := cfg
	cfgNoPwd.DigestPassword = ""
	_, authHeaderNoPwd, _, err := computeAKAAuth(cfgNoPwd, chal, req)
	if err != nil {
		t.Fatalf("computeAKAAuth without password: %v", err)
	}

	// The two responses MUST be different — proving the password is used
	if authHeaderWithPwd == authHeaderNoPwd {
		t.Errorf("response with password == response without password\n  with:    %s\n  without: %s",
			authHeaderWithPwd, authHeaderNoPwd)
	}

	// The response should NOT be the empty-password response
	if strings.Contains(authHeaderWithPwd, `response=""`) {
		t.Errorf("response is empty despite DigestPassword being set: %s", authHeaderWithPwd)
	}

	t.Logf("With password:    %s", authHeaderWithPwd)
	t.Logf("Without password: %s", authHeaderNoPwd)
}

// TestIsPlainMD5Algorithm covers the algorithm detection.
func TestIsPlainMD5Algorithm(t *testing.T) {
	cases := []struct {
		algorithm string
		want      bool
	}{
		{"MD5", true},
		{"md5", true},
		{"AKAv1-MD5", false},
		{"AKAv2-MD5", false},
		{"", false},
		{"SHA-256", false},
	}
	for _, c := range cases {
		got := isPlainMD5Algorithm(c.algorithm)
		if got != c.want {
			t.Errorf("isPlainMD5Algorithm(%q) = %v, want %v", c.algorithm, got, c.want)
		}
	}
}

// Ensure sim.AKAResult is used to avoid unused import
var _ sim.AKAResult
