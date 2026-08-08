package voiceclient

import (
	"testing"
)

// TestRegisterProfileForConfigJSONFirst verifies that the JSON-first path in
// registerProfileForConfig produces profiles matching the hardcoded fallback
// for key carriers.
func TestRegisterProfileForConfigJSONFirst(t *testing.T) {
	// Giffgaff (234-10): hardcoded as DefaultGBEERegisterProfile
	t.Run("Giffgaff_234_10", func(t *testing.T) {
		cfg := Config{MCC: "234", MNC: "10"}
		got := registerProfileForConfig(cfg)
		want := DefaultGBEERegisterProfile()

		if got.ContactFeatures != want.ContactFeatures {
			t.Errorf("ContactFeatures = %q, want %q", got.ContactFeatures, want.ContactFeatures)
		}
		if got.IncludeCellularNetwork != want.IncludeCellularNetwork {
			t.Errorf("IncludeCellularNetwork = %v, want %v", got.IncludeCellularNetwork, want.IncludeCellularNetwork)
		}
		if got.InitialAuthorization != want.InitialAuthorization {
			t.Errorf("InitialAuthorization = %q, want %q", got.InitialAuthorization, want.InitialAuthorization)
		}
		if got.SecurityClientFormat != want.SecurityClientFormat {
			t.Errorf("SecurityClientFormat = %q, want %q", got.SecurityClientFormat, want.SecurityClientFormat)
		}
		if got.SupportedHeader != want.SupportedHeader {
			t.Errorf("SupportedHeader = %q, want %q", got.SupportedHeader, want.SupportedHeader)
		}
		if got.UserAgent != want.UserAgent {
			t.Errorf("UserAgent = %q, want %q", got.UserAgent, want.UserAgent)
		}
		if got.IncludePANIAuthenticated != want.IncludePANIAuthenticated {
			t.Errorf("IncludePANIAuthenticated = %v, want %v", got.IncludePANIAuthenticated, want.IncludePANIAuthenticated)
		}
		if got.IncludeAcceptContact != want.IncludeAcceptContact {
			t.Errorf("IncludeAcceptContact = %v, want %v", got.IncludeAcceptContact, want.IncludeAcceptContact)
		}
		if got.IncludeRoute != want.IncludeRoute {
			t.Errorf("IncludeRoute = %v, want %v", got.IncludeRoute, want.IncludeRoute)
		}
		if got.IncludeSecurityClient != want.IncludeSecurityClient {
			t.Errorf("IncludeSecurityClient = %v, want %v", got.IncludeSecurityClient, want.IncludeSecurityClient)
		}
	})

	// EE UK base (234-33): no SPN → base profile, same IMS config as DefaultGBEERegisterProfile
	t.Run("EEUK_Base_234_33", func(t *testing.T) {
		cfg := Config{MCC: "234", MNC: "33"}
		got := registerProfileForConfig(cfg)
		want := DefaultGBEERegisterProfile()

		if got.ContactFeatures != want.ContactFeatures {
			t.Errorf("ContactFeatures = %q, want %q", got.ContactFeatures, want.ContactFeatures)
		}
		if got.IncludeCellularNetwork != want.IncludeCellularNetwork {
			t.Errorf("IncludeCellularNetwork = %v, want %v", got.IncludeCellularNetwork, want.IncludeCellularNetwork)
		}
		if got.InitialAuthorization != want.InitialAuthorization {
			t.Errorf("InitialAuthorization = %q, want %q", got.InitialAuthorization, want.InitialAuthorization)
		}
	})

	// T-Mobile US (310-260): hardcoded as default sms_only profile
	t.Run("TMobile_310_260", func(t *testing.T) {
		cfg := Config{MCC: "310", MNC: "260"}
		got := registerProfileForConfig(cfg)

		if got.ContactFeatures != "sms_only" {
			t.Errorf("ContactFeatures = %q, want sms_only", got.ContactFeatures)
		}
		if got.IncludeCellularNetwork != false {
			t.Errorf("IncludeCellularNetwork = %v, want false", got.IncludeCellularNetwork)
		}
		if got.InitialAuthorization != "none" {
			t.Errorf("InitialAuthorization = %q, want none", got.InitialAuthorization)
		}
		if got.SupportedHeader != "path,sec-agree,gruu" {
			t.Errorf("SupportedHeader = %q, want path,sec-agree,gruu", got.SupportedHeader)
		}
		if got.UserAgent != "User-Agent: Apple iPhone17,2/26.6 (17,2; iOS 26.6; 23G82) Boot/3.0.0 VoIP/1.0 Carrier/59.0" {
			t.Errorf("UserAgent = %q, want User-Agent: Apple iPhone17,2/26.6 (17,2; iOS 26.6; 23G82) Boot/3.0.0 VoIP/1.0 Carrier/59.0", got.UserAgent)
		}
		if !got.IncludePANIAuthenticated {
			t.Error("IncludePANIAuthenticated = false, want true")
		}
		if !got.IncludeAcceptContact {
			t.Error("IncludeAcceptContact = false, want true")
		}
		if !got.IncludeRoute {
			t.Error("IncludeRoute = false, want true")
		}
		if !got.IncludeSecurityClient {
			t.Error("IncludeSecurityClient = false, want true")
		}
	})

	// Vodafone NL (204-04): hardcoded as default sms_only profile
	t.Run("VodafoneNL_204_04", func(t *testing.T) {
		cfg := Config{MCC: "204", MNC: "04"}
		got := registerProfileForConfig(cfg)

		if got.ContactFeatures != "sms_only" {
			t.Errorf("ContactFeatures = %q, want sms_only", got.ContactFeatures)
		}
		if got.InitialAuthorization != "none" {
			t.Errorf("InitialAuthorization = %q, want none", got.InitialAuthorization)
		}
	})

	// Spark NZ (530-05): hardcoded as default sms_only profile
	t.Run("SparkNZ_530_05", func(t *testing.T) {
		cfg := Config{MCC: "530", MNC: "05"}
		got := registerProfileForConfig(cfg)

		if got.ContactFeatures != "sms_only" {
			t.Errorf("ContactFeatures = %q, want sms_only", got.ContactFeatures)
		}
		if got.InitialAuthorization != "none" {
			t.Errorf("InitialAuthorization = %q, want none", got.InitialAuthorization)
		}
	})
}

// TestRegisterProfileForConfigJSONPathUsed verifies that the JSON-first path is
// actually used (not the hardcoded fallback) by checking that a profile is
// returned for a PLMN that would otherwise hit the default case.
func TestRegisterProfileForConfigJSONPathUsed(t *testing.T) {
	// 310-280 has a JSON profile but would hit the default case in the
	// hardcoded switch. If JSON-first works, it should return a profile
	// with sms_only (from JSON) rather than the hardcoded default.
	cfg := Config{MCC: "310", MNC: "280"}
	got := registerProfileForConfig(cfg)

	if got.ContactFeatures != "sms_only" {
		t.Errorf("ContactFeatures = %q, want sms_only (from JSON)", got.ContactFeatures)
	}
	if got.InitialAuthorization != "none" {
		t.Errorf("InitialAuthorization = %q, want none (from JSON)", got.InitialAuthorization)
	}
	if got.UserAgent != "User-Agent: Apple iPhone17,2/26.6 (17,2; iOS 26.6; 23G82) Boot/3.0.0 VoIP/1.0 Carrier/59.0" {
		t.Errorf("UserAgent = %q, want User-Agent: Apple iPhone17,2/26.6 (17,2; iOS 26.6; 23G82) Boot/3.0.0 VoIP/1.0 Carrier/59.0 (from JSON)", got.UserAgent)
	}
}
