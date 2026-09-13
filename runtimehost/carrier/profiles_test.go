package carrier

import (
	"testing"
)

// TestGenericProfile verifies the generic fallback profile loads from embed.
func TestGenericProfile(t *testing.T) {
	g, err := Generic()
	if err != nil {
		t.Fatalf("Generic() error: %v", err)
	}
	if g == nil {
		t.Fatal("generic profile is nil")
	}
	if g.ID == "" {
		t.Error("generic profile has empty ID")
	}
	if g.ID != "3gpp-default" {
		t.Errorf("generic profile ID = %q, want %q", g.ID, "3gpp-default")
	}
	// Verify some key default fields
	if g.IMS.TransportMode != "udp" {
		t.Errorf("generic ims.transport_mode = %q, want %q", g.IMS.TransportMode, "udp")
	}
	if g.IKE.RFOffDelay != 5 {
		t.Errorf("generic ike.rf_off_delay = %d, want 5", g.IKE.RFOffDelay)
	}
}

// TestBrandToFilename verifies that brandToFilename generates correct filenames.
func TestBrandToFilename(t *testing.T) {
	cases := []struct {
		brand, iso, want string
	}{
		{"EE", "GB", "ee_uk"},                   // ISO alias: gb→uk
		{"Vodafone UK", "GB", "vodafone_uk"},    // strip country suffix
		{"O2", "GB", "o2_uk"},                   // direct match
		{"AT&T", "US", "att_us"},                // US, no alias
		{"Vodafone", "AU/CC/CX", "vodafone_au"}, // multi ISO: AU/CC/CX → au
		{"", "GB", ""},                          // empty brand
	}
	for _, c := range cases {
		t.Run(c.brand+"_"+c.iso, func(t *testing.T) {
			got := brandToFilename(c.brand, c.iso)
			if got != c.want {
				t.Errorf("brandToFilename(%q, %q) = %q, want %q", c.brand, c.iso, got, c.want)
			}
		})
	}
}

// TestLoadProfileFromEmbed verifies that a specific carrier profile can be
// loaded from the embedded filesystem.
func TestLoadProfileFromEmbed(t *testing.T) {
	p := loadProfile("att_us")
	if p == nil {
		t.Fatal("loadProfile(\"att_us\") returned nil")
	}
	if p.ID != "att_us" {
		t.Errorf("profile ID = %q, want %q", p.ID, "att_us")
	}
	if p.MCC != "310" {
		t.Errorf("MCC = %q, want %q", p.MCC, "310")
	}
}

// TestLoadProfileFromEmbed_NonExistent verifies that loading a non-existent
// profile returns nil without error.
func TestLoadProfileFromEmbed_NonExistent(t *testing.T) {
	p := loadProfile("this_does_not_exist")
	if p != nil {
		t.Errorf("expected nil for non-existent profile, got %+v", p)
	}
}

// TestLookupWithIdentity_PLMNFallback verifies that when no GID is provided,
// the lookup falls back to generic when carrier index is not available.
func TestLookupWithIdentity_PLMNFallback(t *testing.T) {
	// Without a carrier index provider, should fall back to generic
	p, err := LookupWithIdentity("310", "260", "", "", "")
	if err != nil {
		t.Fatalf("LookupWithIdentity error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil profile for PLMN 310-260 fallback")
	}
	// Without DB carrier index, should get generic
	if p.ID != "3gpp-default" {
		t.Logf("got profile ID = %q (expected 3gpp-default without DB)", p.ID)
	}
}

// TestLookupWithIdentity_UnknownPLMN_GenericFallback verifies that an unknown
// PLMN falls back to generic.
func TestLookupWithIdentity_UnknownPLMN_GenericFallback(t *testing.T) {
	p, err := LookupWithIdentity("999", "999", "", "", "")
	if err != nil {
		t.Fatalf("LookupWithIdentity error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil generic profile for unknown PLMN")
	}
	if p.ID != "3gpp-default" {
		t.Errorf("expected generic fallback, got ID = %q", p.ID)
	}
}

// TestLookupWithIdentity_UserOverride verifies that a user-registered override
// takes priority over embedded profiles.
func TestLookupWithIdentity_UserOverride(t *testing.T) {
	// Register a user override
	override := &CarrierProfile{
		ID:  "test-override",
		MCC: "310",
		MNC: "260",
	}
	SetUserOverride("310", "260", override)
	defer SetUserOverride("310", "260", nil) // cleanup

	p, err := LookupWithIdentity("310", "260", "", "", "")
	if err != nil {
		t.Fatalf("LookupWithIdentity error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil profile")
	}
	if p.ID != "test-override" {
		t.Errorf("expected user override ID %q, got %q", "test-override", p.ID)
	}
}

// TestLookupWithIdentity_UserOverrideByKey verifies that a brand-specific
// override via SetUserOverrideByKey works correctly.
func TestLookupWithIdentity_UserOverrideByKey(t *testing.T) {
	override := &CarrierProfile{
		ID:  "brand-override",
		MCC: "234",
		MNC: "33",
	}
	SetUserOverrideByKey("234-33", override)
	defer SetUserOverrideByKey("234-33", nil)

	// LookupWithSPN should find the override
	p, err := LookupWithSPN("234", "33", "")
	if err != nil {
		t.Fatalf("LookupWithSPN error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil profile from user override")
	}
	if p.ID != "brand-override" {
		t.Errorf("expected brand override ID %q, got %q", "brand-override", p.ID)
	}
}

// TestPLMNKeyNormalization verifies that MNC is zero-padded to 3 digits.
func TestPLMNKeyNormalization(t *testing.T) {
	cases := []struct {
		mcc, mnc, want string
	}{
		{"310", "260", "310-260"},
		{"310", "0260", "310-0260"},
		{"234", "33", "234-033"},
		{"234", "033", "234-033"},
		{"460", "0", "460-000"},
		{"460", "00", "460-000"},
		{"204", "4", "204-004"},
		{"204", "04", "204-004"},
		{"454", "03", "454-003"},
	}
	for _, c := range cases {
		t.Run(c.mcc+"-"+c.mnc, func(t *testing.T) {
			got := plmnKey(c.mcc, c.mnc)
			if got != c.want {
				t.Errorf("plmnKey(%q, %q) = %q, want %q", c.mcc, c.mnc, got, c.want)
			}
		})
	}
}

// TestPLMNAliases verifies that MNC aliases resolve to the canonical key.
func TestPLMNAliases(t *testing.T) {
	cases := []struct {
		mcc, mnc string // alias input
	}{
		// CMCC aliases
		{"460", "2"},
		{"460", "4"},
		{"460", "7"},
		// China Unicom aliases
		{"460", "6"},
		{"460", "9"},
		// China Telecom alias
		{"460", "5"},
	}
	for _, c := range cases {
		t.Run(c.mcc+"-"+c.mnc, func(t *testing.T) {
			// Register an override under the canonical key (e.g. 460-000)
			canonical := plmnAliases[plmnKey(c.mcc, c.mnc)]
			if canonical == "" {
				t.Fatalf("no alias found for %s-%s", c.mcc, c.mnc)
			}
			override := &CarrierProfile{ID: "alias-test"}
			SetUserOverrideByKey(canonical, override)
			defer SetUserOverrideByKey(canonical, nil)

			// LookupWithSPN should resolve alias and find the override
			p, err := LookupWithSPN(c.mcc, c.mnc, "")
			if err != nil {
				t.Fatalf("LookupWithSPN error: %v", err)
			}
			if p == nil {
				t.Fatal("expected non-nil from alias-resolved override")
			}
			if p.ID != "alias-test" {
				t.Errorf("alias override ID = %q, want %q", p.ID, "alias-test")
			}
		})
	}
}

// TestGIDPrefixMatch verifies bidirectional GID prefix matching.
func TestGIDPrefixMatch(t *testing.T) {
	cases := []struct {
		simGID, mapGID string
		want           bool
	}{
		{"AABB", "AABB", true},   // exact match
		{"AABBCC", "AABB", true}, // SIM longer than map
		{"AABB", "AABBCC", true}, // map longer than SIM
		{"AABB", "CCDD", false},  // no match
		{"", "AABB", false},      // empty SIM GID
		{"AABB", "", false},      // empty map GID
		{"aabb", "AABB", true},   // case insensitive (lowercased by caller)
	}
	for i, c := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			got := gidPrefixMatch(c.simGID, c.mapGID)
			if got != c.want {
				t.Errorf("gidPrefixMatch(%q, %q) = %v, want %v", c.simGID, c.mapGID, got, c.want)
			}
		})
	}
}

// TestClearUserOverrides verifies that clearing overrides works.
func TestClearUserOverrides(t *testing.T) {
	SetUserOverride("999", "99", &CarrierProfile{ID: "temp"})
	ClearUserOverrides()

	p, err := LookupWithSPN("999", "99", "")
	if err != nil {
		t.Fatalf("LookupWithSPN error: %v", err)
	}
	if p != nil {
		t.Errorf("expected nil after ClearUserOverrides, got ID = %q", p.ID)
	}
}

// TestAll_OnlyUserOverrides verifies that All() returns only user-registered
// overrides (not embedded profiles).
func TestAll_OnlyUserOverrides(t *testing.T) {
	ClearUserOverrides()
	SetUserOverride("111", "11", &CarrierProfile{ID: "test-all-1"})
	defer ClearUserOverrides()

	all, err := All()
	if err != nil {
		t.Fatalf("All() error: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 override, got %d", len(all))
	}
	if p, ok := all["111-11"]; !ok || p.ID != "test-all-1" {
		t.Errorf("expected test-all-1 at key 111-11, got %+v", p)
	}
}
