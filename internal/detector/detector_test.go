package detector_test

import (
	"strings"
	"testing"

	"github.com/navikt/actologger/internal/detector"
)

func TestNamesAreSorted(t *testing.T) {
	t.Parallel()

	if got, want := strings.Join(detector.Names(), ","), "mini-shai-hulud,trivy"; got != want {
		t.Fatalf("Names() = %q, want %q", got, want)
	}
}

func TestTrivyActionRefMatchesBothShapes(t *testing.T) {
	t.Parallel()

	def, ok := detector.Lookup(detector.NameTrivy)
	if !ok {
		t.Fatal("Lookup(trivy) = false")
	}

	result := detector.Scan(def, []detector.ExtractedLogFile{{
		Name:    "run.txt",
		Content: "uses actions/checkout@70379aad1a8b40919ce8b382d3cd7d0315cde1d0\nresolved aquasecurity/trivy-action version (SHA:f77738448eec70113cf711656914b61905b3bd47)",
	}})

	if len(result.Matches) != 2 {
		t.Fatalf("len(Matches) = %d, want 2", len(result.Matches))
	}
	if !result.IsFinding {
		t.Fatal("IsFinding = false, want true")
	}
}

func TestMiniShaiHuludSuppressesSameLineMatch(t *testing.T) {
	t.Parallel()

	def, ok := detector.Lookup(detector.NameMiniShaiHulud)
	if !ok {
		t.Fatal("Lookup(mini-shai-hulud) = false")
	}

	result := detector.Scan(def, []detector.ExtractedLogFile{{
		Name:    "run.txt",
		Content: "initialized global blocklist: gh-token-monitor",
	}})

	if len(result.Matches) != 0 {
		t.Fatalf("len(Matches) = %d, want 0", len(result.Matches))
	}
	if len(result.SuppressedMatches) != 1 {
		t.Fatalf("len(SuppressedMatches) = %d, want 1", len(result.SuppressedMatches))
	}
	if got, want := result.SuppressedMatches[0].Reason, "harden-runner-blocklist"; got != want {
		t.Fatalf("Reason = %q, want %q", got, want)
	}
}

func TestMiniShaiHuludNeedsTwoMediumMatches(t *testing.T) {
	t.Parallel()

	def, _ := detector.Lookup(detector.NameMiniShaiHulud)

	one := detector.Scan(def, []detector.ExtractedLogFile{{
		Name:    "run.txt",
		Content: "dial filev2.getsession.org",
	}})
	if one.IsFinding {
		t.Fatal("one medium match produced finding")
	}

	two := detector.Scan(def, []detector.ExtractedLogFile{{
		Name:    "run.txt",
		Content: "dial filev2.getsession.org\ndial seed1.getsession.org",
	}})
	if !two.IsFinding {
		t.Fatal("two medium matches did not produce finding")
	}
}

func TestLineNumbersAndSummariesFollowSpec(t *testing.T) {
	t.Parallel()

	def, _ := detector.Lookup(detector.NameMiniShaiHulud)

	result := detector.Scan(def, []detector.ExtractedLogFile{
		{
			Name:    "one.txt",
			Content: "a\ngh-token-monitor",
		},
		{
			Name:    "two.txt",
			Content: "seed1.getsession.org\nseed2.getsession.org",
		},
	})

	if len(result.Matches) != 3 {
		t.Fatalf("len(Matches) = %d, want 3", len(result.Matches))
	}

	if got, want := result.Matches[0].Line, 10; got != want {
		t.Fatalf("first line = %d, want %d", got, want)
	}
	if got, want := result.Matches[1].Line, 13; got != want {
		t.Fatalf("second file first line = %d, want %d", got, want)
	}
	if got, want := result.MatchSummary, "persistence:gh-token-monitor; network-ioc:seed1.getsession.org; network-ioc:seed2.getsession.org"; got != want {
		t.Fatalf("MatchSummary = %q, want %q", got, want)
	}
}

func TestSnippetIsPreviousCurrentNextAndTruncated(t *testing.T) {
	t.Parallel()

	def, _ := detector.Lookup(detector.NameMiniShaiHulud)
	long := strings.Repeat("x", 250)

	result := detector.Scan(def, []detector.ExtractedLogFile{{
		Name:    "run.txt",
		Content: "before\n" + long + " gh-token-monitor\nafter",
	}})

	if len(result.Matches) != 1 {
		t.Fatalf("len(Matches) = %d, want 1", len(result.Matches))
	}
	if got := len([]rune(result.Matches[0].Snippet)); got != 200 {
		t.Fatalf("snippet length = %d, want 200", got)
	}
}
