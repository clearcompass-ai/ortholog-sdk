package tests

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// v7.5 hard-cut: v6 removed from the policy table. v7 is the only
// active version. v6 bytes reject as unknown. These tests lock in
// the hard-cut discipline in version_policy.go.

func TestVersionPolicy_V7IsActive(t *testing.T) {
	t.Parallel()
	state, known := envelope.PolicyFor(7)
	if !known {
		t.Fatal("v7 must be in policy table")
	}
	if state != envelope.VersionActive {
		t.Errorf("v7 state = %s, want ACTIVE", state)
	}
}

func TestVersionPolicy_V6IsUnknown(t *testing.T) {
	t.Parallel()
	_, known := envelope.PolicyFor(6)
	if known {
		t.Error("v6 must NOT be in policy table (v7.5 hard cut)")
	}
}

func TestVersionPolicy_V4IsUnknown(t *testing.T) {
	t.Parallel()
	_, known := envelope.PolicyFor(4)
	if known {
		t.Error("v4 must NOT be in policy table")
	}
}

func TestVersionPolicy_ActiveVersionReturnsSeven(t *testing.T) {
	t.Parallel()
	if got := envelope.ActiveVersion(); got != 7 {
		t.Errorf("ActiveVersion() = %d, want 7", got)
	}
}

func TestVersionPolicy_KnownVersionsContainsV7(t *testing.T) {
	t.Parallel()
	versions := envelope.KnownVersions()
	found := false
	for _, v := range versions {
		if v == 7 {
			found = true
		}
	}
	if !found {
		t.Error("KnownVersions must contain v7")
	}
}

func TestCheckReadAllowed_V7(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckReadAllowed(7); err != nil {
		t.Errorf("CheckReadAllowed(v7) = %v, want nil", err)
	}
}

func TestCheckReadAllowed_V6Rejected(t *testing.T) {
	t.Parallel()
	err := envelope.CheckReadAllowed(6)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("CheckReadAllowed(v6) = %v, want ErrUnknownVersion (hard cut)", err)
	}
}

func TestCheckReadAllowed_UnknownVersion(t *testing.T) {
	t.Parallel()
	err := envelope.CheckReadAllowed(99)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("CheckReadAllowed(99) = %v, want ErrUnknownVersion", err)
	}
}

func TestCheckWriteAllowed_V7(t *testing.T) {
	t.Parallel()
	if err := envelope.CheckWriteAllowed(7); err != nil {
		t.Errorf("CheckWriteAllowed(v7) = %v, want nil", err)
	}
}

func TestCheckWriteAllowed_V6Rejected(t *testing.T) {
	t.Parallel()
	err := envelope.CheckWriteAllowed(6)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("CheckWriteAllowed(v6) = %v, want ErrUnknownVersion (hard cut)", err)
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
