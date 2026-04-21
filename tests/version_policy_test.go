package tests

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

func TestVersionPolicy_V6IsGenesisActive(t *testing.T) {
	t.Parallel()
	state, known := envelope.PolicyFor(6)
	if !known {
		t.Fatal("v6 must be in policy table")
	}
	if state != envelope.VersionActive {
		t.Errorf("v6 state = %s, want ACTIVE", state)
	}
}

func TestVersionPolicy_V4IsUnknown(t *testing.T) {
	t.Parallel()
	_, known := envelope.PolicyFor(4)
	if known {
		t.Error("v4 must NOT be in policy table (clean v6 genesis)")
	}
}

func TestVersionPolicy_ActiveVersionReturnsSix(t *testing.T) {
	t.Parallel()
	if got := envelope.ActiveVersion(); got != 6 {
		t.Errorf("ActiveVersion() = %d, want 6", got)
	}
}

func TestVersionPolicy_KnownVersionsContainsV6(t *testing.T) {
	t.Parallel()
	versions := envelope.KnownVersions()
	found := false
	for _, v := range versions {
		if v == 6 {
			found = true
		}
	}
	if !found {
		t.Error("KnownVersions must contain v6")
	}
}

func TestCheckReadAllowed_V6(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckReadAllowed(6); err != nil {
		t.Errorf("CheckReadAllowed(v6) = %v, want nil", err)
	}
}

func TestCheckReadAllowed_UnknownVersion(t *testing.T) {
	t.Parallel()
	err := envelope.CheckReadAllowed(99)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("CheckReadAllowed(99) = %v, want ErrUnknownVersion", err)
	}
}

func TestCheckWriteAllowed_V6(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckWriteAllowed(6); err != nil {
		t.Errorf("CheckWriteAllowed(v6) = %v, want nil", err)
	}
}

func TestCheckWriteAllowed_UnknownVersion(t *testing.T) {
	t.Parallel()
	err := envelope.CheckWriteAllowed(99)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("CheckWriteAllowed(99) = %v, want ErrUnknownVersion", err)
	}
}

func TestVersionState_StringRendersAllStates(t *testing.T) {
	t.Parallel()
	cases := map[envelope.VersionState]string{
		envelope.VersionActive:     "ACTIVE",
		envelope.VersionDeprecated: "DEPRECATED",
		envelope.VersionFrozen:     "FROZEN",
		envelope.VersionRevoked:    "REVOKED",
	}
	for state, want := range cases {
		if got := state.String(); got != want {
			t.Errorf("state %d: got %q, want %q", state, got, want)
		}
	}
}
