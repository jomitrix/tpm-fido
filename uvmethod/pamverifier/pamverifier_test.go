package pamverifier

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psanford/tpm-fido/uvmethod"
)

func TestPamVerifierSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	mockPrompt := filepath.Join(tmpDir, "mock-prompt.sh")
	err := os.WriteFile(mockPrompt, []byte("#!/bin/sh\nexit 0\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	v := New(mockPrompt)
	ctx := context.Background()
	outcome, err := v.Verify(ctx, "example.com", "user", "authenticate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != uvmethod.Verified {
		t.Fatalf("expected Verified, got %v", outcome)
	}
}

func TestPamVerifierReject(t *testing.T) {
	tmpDir := t.TempDir()
	mockPrompt := filepath.Join(tmpDir, "mock-prompt.sh")
	err := os.WriteFile(mockPrompt, []byte("#!/bin/sh\nexit 1\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	v := New(mockPrompt)
	ctx := context.Background()
	outcome, err := v.Verify(ctx, "example.com", "user", "authenticate")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != uvmethod.Rejected {
		t.Fatalf("expected Rejected, got %v", outcome)
	}
}

func TestPamVerifierCancel(t *testing.T) {
	tmpDir := t.TempDir()
	mockPrompt := filepath.Join(tmpDir, "mock-prompt.sh")
	err := os.WriteFile(mockPrompt, []byte("#!/bin/sh\nsleep 10\nexit 0\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	v := New(mockPrompt)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	outcome, err := v.Verify(ctx, "example.com", "user", "authenticate")
	if outcome != uvmethod.Rejected {
		t.Fatalf("expected Rejected on context cancel, got %v (err=%v)", outcome, err)
	}
}
