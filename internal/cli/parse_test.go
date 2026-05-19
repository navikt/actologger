package cli_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/navikt/actologger/internal/cli"
	"github.com/navikt/actologger/internal/detector"
)

func TestParseDeduplicatesAndTrimsTargets(t *testing.T) {
	t.Parallel()

	cfg, err := cli.Parse(
		[]string{"--repo", " navikt/a , navikt/b ", "--repo", "navikt/a", "--org", " navikt , navikt "},
		new(bytes.Buffer),
		envWithToken,
		fixedNow,
	)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if got, want := strings.Join(cfg.Repos, ","), "navikt/a,navikt/b"; got != want {
		t.Fatalf("Repos = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.Orgs, ","), "navikt"; got != want {
		t.Fatalf("Orgs = %q, want %q", got, want)
	}
}

func TestParseUsesDetectorDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := cli.Parse(
		[]string{"--repo", "navikt/a", "--detector", detector.NameMiniShaiHulud},
		new(bytes.Buffer),
		envWithToken,
		fixedNow,
	)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	wantSince := time.Date(2026, time.May, 11, 0, 0, 0, 0, time.UTC)
	wantUntil := fixedNow().UTC()
	if !cfg.Since.Equal(wantSince) {
		t.Fatalf("Since = %s, want %s", cfg.Since, wantSince)
	}
	if !cfg.Until.Equal(wantUntil) {
		t.Fatalf("Until = %s, want %s", cfg.Until, wantUntil)
	}
}

func TestParseRejectsNormalizedEdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "workers",
			args: []string{"--repo", "navikt/a", "--workers", "0"},
			want: "invalid --workers",
		},
		{
			name: "repo-format",
			args: []string{"--repo", "navikt"},
			want: "invalid --repo",
		},
		{
			name: "log-dir-all",
			args: []string{"--repo", "navikt/a", "--log-dir-all"},
			want: "invalid --log-dir-all",
		},
		{
			name: "missing-targets",
			args: []string{},
			want: "missing scan targets",
		},
		{
			name: "token-flag-disabled",
			args: []string{"--token", "secret"},
			want: "token flags are disabled",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := cli.Parse(tt.args, new(bytes.Buffer), envWithToken, fixedNow)
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %q, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParseAcceptsShortAliasesWithoutDuplicatingHelpFlags(t *testing.T) {
	t.Parallel()

	stderr := new(bytes.Buffer)
	cfg, err := cli.Parse([]string{"-r", "navikt/a", "-f=csv", "-w", "3", "-v"}, stderr, envWithToken, fixedNow)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := cfg.Format, "csv"; string(got) != want {
		t.Fatalf("Format = %q, want %q", got, want)
	}
	if got, want := cfg.Workers, 3; got != want {
		t.Fatalf("Workers = %d, want %d", got, want)
	}
	if !cfg.Verbose {
		t.Fatal("Verbose = false, want true")
	}
}

func TestHelpOutputShowsCanonicalFlagsOnce(t *testing.T) {
	t.Parallel()

	stderr := new(bytes.Buffer)
	_, err := cli.Parse([]string{"--help"}, stderr, envWithToken, fixedNow)
	if err == nil {
		t.Fatal("Parse() error = nil, want help error")
	}

	help := stderr.String()
	for _, unwanted := range []string{"\n  -r value\n", "\n  -f string\n", "\n  -w int\n", "\n  -t string\n", "\n  -token string\n"} {
		if strings.Contains(help, unwanted) {
			t.Fatalf("help output unexpectedly contains %q:\n%s", unwanted, help)
		}
	}
	for _, wanted := range []string{"-repo value", "-format string", "-workers int", "-verbose"} {
		if !strings.Contains(help, wanted) {
			t.Fatalf("help output missing %q:\n%s", wanted, help)
		}
	}
	if strings.Contains(help, "-token") || strings.Contains(help, "\n  -t ") {
		t.Fatalf("help output unexpectedly contains token flags:\n%s", help)
	}
}

func fixedNow() time.Time {
	return time.Date(2026, time.May, 18, 16, 0, 0, 0, time.UTC)
}

func envWithToken(key string) string {
	if key == "GITHUB_TOKEN" {
		return "secret"
	}
	return ""
}
