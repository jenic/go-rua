package upstream

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type GPGRunFunc func(context.Context, []byte, ...string) ([]byte, error)

// GPGVerifier exports externally anchored keys from the user's keyring and
// verifies in a new isolated keyring. It never imports keys from a release.
type GPGVerifier struct {
	Run GPGRunFunc
}

func (v GPGVerifier) Verify(ctx context.Context, payload, signature []byte, fingerprints []string) (SignatureResult, error) {
	dir, err := os.MkdirTemp("", "go-rua-gpg-payload-*")
	if err != nil {
		return SignatureResult{}, err
	}
	defer os.RemoveAll(dir)
	payloadPath := filepath.Join(dir, "payload")
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		return SignatureResult{}, err
	}
	return v.VerifyFile(ctx, payloadPath, signature, fingerprints)
}

func (v GPGVerifier) VerifyFile(ctx context.Context, payloadPath string, signature []byte, fingerprints []string) (SignatureResult, error) {
	if len(fingerprints) == 0 {
		return SignatureResult{}, fmt.Errorf("no externally anchored fingerprints")
	}
	run := v.Run
	if run == nil {
		run = runGPG
	}
	exportArgs := []string{"gpg", "--batch", "--no-tty", "--export"}
	exportArgs = append(exportArgs, fingerprints...)
	keys, err := run(ctx, nil, exportArgs...)
	if err != nil {
		return SignatureResult{}, fmt.Errorf("export externally anchored keys: %w", err)
	}
	if len(keys) == 0 {
		return SignatureResult{}, fmt.Errorf("export externally anchored keys returned no key material")
	}
	home, err := os.MkdirTemp("", "go-rua-gpg-*")
	if err != nil {
		return SignatureResult{}, err
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return SignatureResult{}, err
	}
	if _, err := run(ctx, keys, "gpg", "--homedir", home, "--batch", "--no-tty", "--import"); err != nil {
		return SignatureResult{}, fmt.Errorf("import anchored keys into isolated keyring: %w", err)
	}
	signaturePath := filepath.Join(home, "signature")
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return SignatureResult{}, err
	}
	status, verifyErr := run(ctx, nil, "gpg", "--homedir", home, "--batch", "--no-tty", "--status-fd=1", "--verify", signaturePath, payloadPath)
	result := parseGPGStatus(status, fingerprints)
	if verifyErr != nil {
		return result, fmt.Errorf("verify isolated signature: %w", verifyErr)
	}
	if !result.Valid {
		return result, fmt.Errorf("isolated signature did not validate under an externally anchored key")
	}
	return result, nil
}

func runGPG(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	var output, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &stderr
	err := cmd.Run()
	if err != nil {
		return output.Bytes(), fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return output.Bytes(), nil
}

func parseGPGStatus(status []byte, fingerprints []string) SignatureResult {
	result := SignatureResult{}
	validCount := 0
	badStatus := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "[GNUPG:]" {
			continue
		}
		switch fields[1] {
		case "BADSIG", "ERRSIG", "NO_PUBKEY":
			badStatus = true
		case "REVKEYSIG":
			result.Revoked = true
		case "KEYEXPIRED", "SIGEXPIRED", "EXPKEYSIG":
			result.Expired = true
		case "VALIDSIG":
			validCount++
			if len(fields) >= 11 {
				result.Fingerprint = strings.ToUpper(fields[2])
				result.KeyAlgorithm, _ = strconv.Atoi(fields[8])
				result.HashAlgorithm, _ = strconv.Atoi(fields[9])
				primary := result.Fingerprint
				if len(fields) >= 12 {
					primary = strings.ToUpper(fields[len(fields)-1])
				}
				result.Valid = containsFold(fingerprints, result.Fingerprint) || containsFold(fingerprints, primary)
				if result.Valid && containsFold(fingerprints, primary) {
					result.Fingerprint = primary
				}
			}
		}
	}
	strongKey := result.KeyAlgorithm == 1 || result.KeyAlgorithm == 2 || result.KeyAlgorithm == 3 || result.KeyAlgorithm == 18 || result.KeyAlgorithm == 19 || result.KeyAlgorithm == 22
	strongHash := result.HashAlgorithm == 8 || result.HashAlgorithm == 9 || result.HashAlgorithm == 10 || result.HashAlgorithm == 11
	result.Valid = result.Valid && validCount == 1 && strongKey && strongHash && !badStatus && !result.Revoked && !result.Expired
	return result
}
