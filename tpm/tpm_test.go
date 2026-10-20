package tpm_test

import (
	"crypto/sha256"
	"os"
	"testing"

	"github.com/psanford/tpm-fido/tpm"
)

func TestTPM_PCRBinding(t *testing.T) {
	devicePath := os.Getenv("TPM_DEVICE")
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}
	if _, err := os.Stat(devicePath); err != nil {
		t.Skipf("TPM device %s not available: %v", devicePath, err)
	}

	appParam := sha256.Sum256([]byte("example.com"))

	// 1. Test key creation and signing with PCR sealing (0, 2, 7)
	t.Run("SealedKey_SignSuccess", func(t *testing.T) {
		tpmInstance, err := tpm.New(devicePath, tpm.WithPCRs([]int{0, 2, 7}))
		if err != nil {
			t.Fatalf("tpm.New failed: %v", err)
		}

		keyHandle, x, y, err := tpmInstance.RegisterKey(appParam[:])
		if err != nil {
			t.Fatalf("RegisterKey failed: %v", err)
		}
		if x == nil || y == nil || len(keyHandle) == 0 {
			t.Fatalf("RegisterKey returned invalid values")
		}

		digest := sha256.Sum256([]byte("sample challenge to sign"))
		sig, err := tpmInstance.SignASN1(keyHandle, appParam[:], digest[:])
		if err != nil {
			t.Fatalf("SignASN1 failed for sealed key: %v", err)
		}
		if len(sig) == 0 {
			t.Fatalf("SignASN1 returned empty signature")
		}
	})

	// 2. Test key creation and signing without PCR sealing (legacy mode)
	t.Run("UnsealedKey_SignSuccess", func(t *testing.T) {
		tpmInstance, err := tpm.New(devicePath)
		if err != nil {
			t.Fatalf("tpm.New failed: %v", err)
		}

		keyHandle, _, _, err := tpmInstance.RegisterKey(appParam[:])
		if err != nil {
			t.Fatalf("RegisterKey failed: %v", err)
		}

		digest := sha256.Sum256([]byte("another challenge"))
		sig, err := tpmInstance.SignASN1(keyHandle, appParam[:], digest[:])
		if err != nil {
			t.Fatalf("SignASN1 failed for unsealed key: %v", err)
		}
		if len(sig) == 0 {
			t.Fatalf("SignASN1 returned empty signature")
		}
	})
}
