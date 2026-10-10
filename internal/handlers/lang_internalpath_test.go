package handlers

import "testing"

func TestInternalPathRejectsOffSiteTargets(t *testing.T) {
	for _, s := range []string{"", "x", "//evil.com", "/\\evil.com", "/\\/evil.com", "https://evil.com", "/\tevil", "/a\r\nLocation: x"} {
		if got := internalPath(s); got != "" {
			t.Errorf("internalPath(%q) = %q, want empty", s, got)
		}
	}
	for _, s := range []string{"/", "/sites", "/forms/abc?page=2", "/a/b#c"} {
		if got := internalPath(s); got != s {
			t.Errorf("internalPath(%q) = %q, want %q", s, got, s)
		}
	}
}
