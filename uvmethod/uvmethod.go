// Package uvmethod abstracts how tpm-fido performs *built-in* user
// verification for CTAP 2.1 internal UV (the Windows-Hello-style path, where
// the browser shows no PIN box and the authenticator verifies the user on its
// own side).
package uvmethod

import "context"

// Outcome is the result of a user-verification attempt.
type Outcome int

const (
	// Verified: the user was successfully verified.
	Verified Outcome = iota
	// Rejected: the user failed verification (wrong credentials or cancel).
	Rejected
	// Unavailable: verification could not be attempted (display unavailable, prompt missing).
	Unavailable
	// LockedOut: too many failed attempts; the backend refuses further tries.
	LockedOut
)

// Verifier performs one built-in user-verification interaction.
type Verifier interface {
	// Verify runs the interaction and blocks until it resolves, the ctx is
	// canceled, or an internal timeout fires. It must not panic and must
	// return a terminal Outcome.
	Verify(ctx context.Context, rpID, user, mode string) (Outcome, error)

	// Name is a short identifier for logs ("pam", ...).
	Name() string
}
