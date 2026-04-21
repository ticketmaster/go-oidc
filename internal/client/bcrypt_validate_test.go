package client

// Tests for the tm.1 fork patch: validateSecret auto-detects bcrypt hashes.
// See forks/go-oidc/PATCHES.md for rationale and retirement path.

import (
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"golang.org/x/crypto/bcrypt"
)

func TestValidateSecret_Plaintext_Match(t *testing.T) {
	c := &goidc.Client{Secret: "hunter2"}
	if err := validateSecret(c, "hunter2"); err != nil {
		t.Fatalf("plaintext match should succeed, got: %v", err)
	}
}

func TestValidateSecret_Plaintext_Mismatch(t *testing.T) {
	c := &goidc.Client{Secret: "hunter2"}
	err := validateSecret(c, "wrong")
	if err == nil {
		t.Fatal("plaintext mismatch must return an error")
	}
	if !strings.Contains(err.Error(), "invalid client secret") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateSecret_BcryptHash_Match(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt generate: %v", err)
	}
	c := &goidc.Client{Secret: string(hash)}
	if err := validateSecret(c, "hunter2"); err != nil {
		t.Fatalf("bcrypt-hashed Secret + correct plaintext must succeed, got: %v", err)
	}
}

func TestValidateSecret_BcryptHash_Mismatch(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt generate: %v", err)
	}
	c := &goidc.Client{Secret: string(hash)}
	err = validateSecret(c, "wrong")
	if err == nil {
		t.Fatal("bcrypt-hashed Secret + wrong plaintext must return an error")
	}
}

// TestValidateSecret_HashReplayAttack guards the security invariant that
// prevents a critical attack: if validateSecret fell through to constant-
// time compare after a failed bcrypt compare, an attacker with DB read
// access could submit the stored bcrypt hash as the plaintext and
// authenticate. This test pins that bcrypt-hashed Secret + submitted
// bcrypt-hash-string is a FAILURE, not success.
func TestValidateSecret_HashReplayAttack(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("the-real-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	c := &goidc.Client{Secret: string(hash)}

	// Attacker submits the hash itself as the "plaintext". bcrypt rejects,
	// and we MUST NOT fall through to constant-time compare (which would
	// trivially match since c.Secret == submitted).
	if err := validateSecret(c, string(hash)); err == nil {
		t.Fatal("submitting the bcrypt hash string as the plaintext must " +
			"fail — falling through to constant-time compare here would be " +
			"a DB-dump replay vulnerability")
	}

	// Correct plaintext still works.
	if err := validateSecret(c, "the-real-secret"); err != nil {
		t.Fatalf("correct plaintext must succeed: %v", err)
	}
}

// TestLooksLikeBcryptHash covers the prefix/length detector. The documented
// pathological case (60-char plaintext starting with "$2x$") is left to
// the fork's validateSecret godoc; this test only pins the positive and
// negative detection contract.
func TestLooksLikeBcryptHash(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", false},
		{"plaintext", "hunter2", false},
		{"60-char non-hash", strings.Repeat("a", 60), false},
		{"wrong prefix", "$1$" + strings.Repeat("a", 57), false},
		{"$2a prefix, wrong length", "$2a$10$short", false},
		{"valid $2a hash", mustBcrypt(t, "x", "$2a"), true},
		{"valid $2b hash", mustBcrypt(t, "x", "$2b"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikeBcryptHash(tc.in); got != tc.want {
				t.Fatalf("looksLikeBcryptHash(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// mustBcrypt generates a bcrypt hash and rewrites its prefix to wantPrefix.
// golang.org/x/crypto/bcrypt always emits $2a$; $2b$ is format-compatible.
func mustBcrypt(t *testing.T, plain, wantPrefix string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	s := string(h)
	if !strings.HasPrefix(s, "$2a$") {
		t.Fatalf("unexpected bcrypt prefix in runtime output: %q", s)
	}
	return wantPrefix + "$" + s[len("$2a$"):]
}

