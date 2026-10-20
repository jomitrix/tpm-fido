package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/psanford/tpm-fido/internal/lencode"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/hkdf"
)

var (
	separator     = []byte("TPM")
	seedSizeBytes = 20
)

type TPM struct {
	devicePath string
	mu         sync.Mutex

	// lastCounter tracks the highest value Counter() has ever returned,
	// so two signatures issued within the same wall-clock second (e.g.
	// GetAssertion for two different non-resident credentials in quick
	// succession) still get strictly increasing values instead of a tie
	// -- a tie or decrease is what RPs use to flag a cloned/replayed
	// authenticator.
	lastCounter uint32

	// pcrs holds the list of PCR indices to seal passkey signing keys to
	// (e.g. [0, 2, 7] for firmware, option ROMs, and Secure Boot state).
	// An empty slice disables PCR sealing.
	pcrs []int
}

type Option func(*TPM)

// WithPCRs configures the PCR registers to seal newly created passkeys to.
func WithPCRs(pcrs []int) Option {
	return func(t *TPM) {
		t.pcrs = append([]int(nil), pcrs...)
	}
}

func (t *TPM) open() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(t.devicePath)
}

func New(devicePath string, opts ...Option) (*TPM, error) {
	t := &TPM{
		devicePath: devicePath,
	}
	for _, opt := range opts {
		opt(t)
	}

	tpm, err := t.open()
	if err != nil {
		return nil, err
	}
	tpm.Close()

	return t, nil
}

func primaryKeyTmpl(seed, applicationParam []byte) tpm2.Public {
	info := append([]byte("tpm-fido-application-key"), applicationParam...)

	r := hkdf.New(sha256.New, seed, []byte{}, info)
	unique := tpm2.ECPoint{
		XRaw: make([]byte, 32),
		YRaw: make([]byte, 32),
	}
	if _, err := io.ReadFull(r, unique.XRaw); err != nil {
		panic(err)
	}
	if _, err := io.ReadFull(r, unique.YRaw); err != nil {
		panic(err)
	}

	return tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagRestricted | tpm2.FlagDecrypt |
			tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			CurveID: tpm2.CurveNISTP256,
			Point:   unique,
		},
	}
}

var baseTime = time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)

func (t *TPM) Counter() uint32 {
	wallClock := uint32(time.Now().Unix() - baseTime.Unix())

	for {
		prev := atomic.LoadUint32(&t.lastCounter)
		next := wallClock
		if next <= prev {
			next = prev + 1
		}
		if atomic.CompareAndSwapUint32(&t.lastCounter, prev, next) {
			return next
		}
	}
}

func (t *TPM) computePCRPolicy(tpm io.ReadWriter, pcrs []int) ([]byte, error) {
	if len(pcrs) == 0 {
		return nil, nil
	}

	sel := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: pcrs,
	}

	trialSess, _, err := tpm2.StartAuthSession(
		tpm,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		nil,
		tpm2.SessionTrial,
		tpm2.AlgNull,
		tpm2.AlgSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("StartAuthSession(trial) failed: %w", err)
	}
	defer tpm2.FlushContext(tpm, trialSess)

	if err := tpm2.PolicyPCR(tpm, trialSess, nil, sel); err != nil {
		return nil, fmt.Errorf("PolicyPCR(trial) failed: %w", err)
	}

	policyDigest, err := tpm2.PolicyGetDigest(tpm, trialSess)
	if err != nil {
		return nil, fmt.Errorf("PolicyGetDigest failed: %w", err)
	}

	return policyDigest, nil
}

// Register a new key with the TPM for the given applicationParam.
// If PCR sealing is configured, the key is cryptographically sealed to
// the selected PCR registers, ensuring it cannot be used if system state changes.
// RegisterKey returns the KeyHandle or an error.
func (t *TPM) RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	randSeed := mustRand(seedSizeBytes)

	primaryTmpl := primaryKeyTmpl(randSeed, applicationParam)

	childTmpl := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagSign,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: tpm2.CurveNISTP256,
			Point: tpm2.ECPoint{
				XRaw: make([]byte, 32),
				YRaw: make([]byte, 32),
			},
		},
	}

	policyDigest, err := t.computePCRPolicy(tpm, t.pcrs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compute PCR policy err: %w", err)
	}

	if len(policyDigest) > 0 {
		// When PCR sealing is active, bind the key directly to the PCR policy digest.
		// Omitting FlagUserWithAuth ensures the key CANNOT be signed with a simple
		// password session, enforcing that the TPM verify the PCR registers in hardware.
		childTmpl.AuthPolicy = policyDigest
	} else {
		// Legacy / unsealed mode: permit standard user authorization
		childTmpl.Attributes |= tpm2.FlagUserWithAuth
	}

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, parentHandle)

	private, public, _, _, _, err := tpm2.CreateKey(tpm, parentHandle, tpm2.PCRSelection{}, "", "", childTmpl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CreateKey (child) err: %w", err)
	}

	var out bytes.Buffer
	enc := lencode.NewEncoder(&out, lencode.SeparatorOpt(separator))

	enc.Encode(private)
	enc.Encode(public)
	enc.Encode(randSeed)
	if len(t.pcrs) > 0 {
		pcrBytes := make([]byte, len(t.pcrs))
		for i, p := range t.pcrs {
			pcrBytes[i] = byte(p)
		}
		enc.Encode(pcrBytes)
	}

	keyHandle, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load child key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, keyHandle)

	pub, _, _, err := tpm2.ReadPublic(tpm, keyHandle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read public key err: %w", err)
	}

	x := new(big.Int).SetBytes(pub.ECCParameters.Point.XRaw)
	y := new(big.Int).SetBytes(pub.ECCParameters.Point.YRaw)

	return out.Bytes(), x, y, nil
}

func (t *TPM) SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tpm, err := t.open()
	if err != nil {
		return nil, fmt.Errorf("open tpm err: %w", err)
	}
	defer tpm.Close()

	dec := lencode.NewDecoder(bytes.NewReader(keyHandle), lencode.SeparatorOpt(separator))

	invalidHandleErr := fmt.Errorf("invalid key handle")

	private, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	public, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	seed, err := dec.Decode()
	if err != nil {
		return nil, invalidHandleErr
	}

	// 4th chunk optionally stores the PCR list used when registering this credential
	var pcrBytes []byte
	chunk, err := dec.Decode()
	if err == nil {
		pcrBytes = chunk
		if _, err := dec.Decode(); err != io.EOF {
			return nil, invalidHandleErr
		}
	} else if err != io.EOF {
		return nil, invalidHandleErr
	}

	srkTemplate := primaryKeyTmpl(seed, applicationParam)

	parentHandle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate)
	if err != nil {
		return nil, fmt.Errorf("CreatePrimary key err: %w", err)
	}

	defer tpm2.FlushContext(tpm, parentHandle)

	key, _, err := tpm2.Load(tpm, parentHandle, "", public, private)
	if err != nil {
		return nil, fmt.Errorf("Load err: %w", err)
	}

	defer tpm2.FlushContext(tpm, key)

	pubObj, _, _, err := tpm2.ReadPublic(tpm, key)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic err: %w", err)
	}

	scheme := &tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}

	var sig *tpm2.Signature
	if len(pubObj.AuthPolicy) > 0 {
		// Key was sealed with a PCR policy. Start a real SessionPolicy session
		// and satisfy PolicyPCR against the system's live PCR registers.
		var pcrs []int
		if len(pcrBytes) > 0 {
			for _, b := range pcrBytes {
				pcrs = append(pcrs, int(b))
			}
		} else if len(t.pcrs) > 0 {
			pcrs = t.pcrs
		} else {
			pcrs = []int{0, 2, 7}
		}

		sel := tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrs,
		}

		policySess, _, err := tpm2.StartAuthSession(
			tpm,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, 16),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256,
		)
		if err != nil {
			return nil, fmt.Errorf("StartAuthSession(policy) failed: %w", err)
		}
		defer tpm2.FlushContext(tpm, policySess)

		if err := tpm2.PolicyPCR(tpm, policySess, nil, sel); err != nil {
			return nil, fmt.Errorf("PolicyPCR failed: %w", err)
		}

		sig, err = tpm2.SignWithSession(tpm, policySess, key, "", digest[:], nil, scheme)
		if err != nil {
			return nil, fmt.Errorf("sign with PCR policy session err (PCR state mismatch/tampered): %w", err)
		}
	} else {
		// Legacy / unsealed key: authenticate with standard password session
		sig, err = tpm2.Sign(tpm, key, "", digest[:], nil, scheme)
		if err != nil {
			return nil, fmt.Errorf("sign err: %w", err)
		}
	}

	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(sig.ECC.R)
		b.AddASN1BigInt(sig.ECC.S)
	})

	return b.Bytes()
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
