package upstream

import "testing"

func TestParseGitHubGitSourceURLSupportsMakepkgTagForms(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		signed bool
	}{
		{name: "plain tag", value: "git+https://github.com/acme/app.git#tag=v1.2.3"},
		{name: "query before fragment", value: "git+https://github.com/acme/app.git?signed#tag=v1.2.3", signed: true},
		{name: "query after fragment", value: "git+https://github.com/acme/app.git#tag=v1.2.3?signed", signed: true},
		{name: "repository without dot git", value: "git+https://github.com/acme/app#tag=v1.2.3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseGitHubGitSourceURL(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if got.Repository.String() != "acme/app" || got.Tag != "v1.2.3" || got.Signed != test.signed {
				t.Fatalf("parsed source = %#v", got)
			}
		})
	}
}

func TestParseGitHubGitSourceURLRejectsUnsupportedAndAmbiguousForms(t *testing.T) {
	for _, value := range []string{
		"https://github.com/acme/app.git#tag=v1.2.3",
		"git+http://github.com/acme/app.git#tag=v1.2.3",
		"git+https://user@github.com/acme/app.git#tag=v1.2.3",
		"git+https://github.com.evil.test/acme/app.git#tag=v1.2.3",
		"git+https://github.com/acme/app.git#branch=main",
		"git+https://github.com/acme/app.git#commit=0123456789012345678901234567890123456789",
		"git+https://github.com/acme/app.git",
		"git+https://github.com/acme/app.git?depth=1#tag=v1.2.3",
		"git+https://github.com/acme/app.git?signed#tag=v1.2.3?signed",
		"git+https://github.com/acme/app.git#tag=v1.2.3%2Fother",
		"git+https://github.com/acme/.git#tag=v1.2.3",
		"git+https://github.com/acme/app.git#tag=../v1.2.3",
		"git+https://github.com/acme/app.git#tag=v1/.hidden",
		"git+https://github.com/acme/app.git#tag=v1/release.lock/next",
		"git+https://github.com/acme/app.git#tag=v1./next",
	} {
		if _, err := ParseGitHubGitSourceURL(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestRewriteGitSourceToCommitPreservesAliasAndPinsIdentity(t *testing.T) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	got, err := rewriteGitSourceToCommit("app::git+https://github.com/acme/app.git?signed#tag=v1.2.4", commit, "github.com")
	if err != nil {
		t.Fatal(err)
	}
	want := "app::git+https://github.com/acme/app.git#commit=" + commit
	if got != want {
		t.Fatalf("rewritten source = %q, want %q", got, want)
	}
}
