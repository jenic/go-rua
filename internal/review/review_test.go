package review

import (
	"io"
	"strings"
	"testing"
)

func TestAnswerDoesNotConsumeNextDecision(t *testing.T) {
	r := strings.NewReader("a\ny\n")
	a, err := Answer(r)
	if a != "a" || err != nil {
		t.Fatal(a, err)
	}
	a, err = Answer(r)
	if a != "y" || err != nil {
		t.Fatal(a, err)
	}
	if _, err = Answer(r); err != io.EOF {
		t.Fatal(err)
	}
}
func TestSafeEscapesTerminalControls(t *testing.T) {
	s := Safe("a\x1b[2J\u202e\nnext")
	if strings.ContainsRune(s, '\x1b') || strings.ContainsRune(s, '\u202e') || !strings.Contains(s, "\nnext") {
		t.Fatal(s)
	}
}
