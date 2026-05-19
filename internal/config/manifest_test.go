package config_test

import (
	"testing"
	"time"

	"github.com/navikt/actologger/internal/config"
)

func TestManifestCanonicalHashSortsCollectionsAndNormalizesUTC(t *testing.T) {
	t.Parallel()

	a := config.Manifest{
		Version:        config.ManifestVersion,
		Detector:       "mini-shai-hulud",
		RequestedSince: time.Date(2026, time.May, 11, 2, 0, 0, 0, time.FixedZone("CEST", 2*60*60)),
		RequestedUntil: time.Date(2026, time.May, 18, 18, 0, 0, 0, time.FixedZone("CEST", 2*60*60)),
		Orgs:           []string{"navikt", "github"},
		Repos:          []string{"navikt/b", "navikt/a"},
	}
	b := config.Manifest{
		Version:        config.ManifestVersion,
		Detector:       "mini-shai-hulud",
		RequestedSince: time.Date(2026, time.May, 11, 0, 0, 0, 0, time.UTC),
		RequestedUntil: time.Date(2026, time.May, 18, 16, 0, 0, 0, time.UTC),
		Orgs:           []string{"github", "navikt"},
		Repos:          []string{"navikt/a", "navikt/b"},
	}

	hashA, err := a.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	hashB, err := b.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}

	if hashA != hashB {
		t.Fatalf("CanonicalHash() mismatch: %q != %q", hashA, hashB)
	}
}
