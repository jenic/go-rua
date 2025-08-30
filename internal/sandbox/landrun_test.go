package sandbox

import "testing"

func TestRunEmptyArgv(t *testing.T) {
	if err := Run(Config{}, nil); err == nil {
		t.Fatalf("expected error for empty argv")
	}
}

func TestRunCaptureEmptyArgv(t *testing.T) {
	if _, _, err := RunCapture(Config{}, nil); err == nil {
		t.Fatalf("expected error for empty argv")
	}
}
