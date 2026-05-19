package scanner_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/detector"
	ghclient "github.com/navikt/actologger/internal/github"
	"github.com/navikt/actologger/internal/scanner"
)

func TestRunStateResumeReplaysFindings(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := config.Config{
		Token:        "secret",
		Format:       config.FormatJSON,
		Detector:     detector.NameMiniShaiHulud,
		Repos:        []string{"navikt/a"},
		Since:        time.Date(2026, 5, 11, 0, 0, 0, 0, time.UTC),
		Until:        time.Date(2026, 5, 18, 16, 0, 0, 0, time.UTC),
		Workers:      1,
		OutputFile:   filepath.Join(dir, "findings.json"),
		ManifestFile: filepath.Join(dir, "scan-manifest.json"),
		StateFile:    filepath.Join(dir, "scan-state.json"),
	}

	svc := &mockGitHub{
		runs: map[string][]ghclient.WorkflowRun{
			"navikt/a": {
				{ID: 2, Name: "CI", URL: "https://example/2", CreatedAt: time.Date(2026, 5, 18, 15, 0, 0, 0, time.UTC)},
				{ID: 1, Name: "CI", URL: "https://example/1", CreatedAt: time.Date(2026, 5, 18, 14, 0, 0, 0, time.UTC)},
			},
		},
		logs: map[int64][]detector.ExtractedLogFile{
			1: {{Name: "one.txt", Content: "gh-token-monitor"}},
			2: {{Name: "two.txt", Content: "filev2.getsession.org\nseed1.getsession.org"}},
		},
	}

	graceful := make(chan struct{})
	if _, err := scanner.Run(context.Background(), scanner.Params{
		Config:       cfg,
		GitHub:       svc,
		Stdout:       new(bytes.Buffer),
		Stderr:       new(bytes.Buffer),
		GracefulStop: graceful,
		Now:          fixedNow,
	}); err != nil {
		t.Fatalf("first Run() error = %v", err)
	}

	svc2 := &mockGitHub{
		runs: svc.runs,
		logs: map[int64][]detector.ExtractedLogFile{},
	}
	if _, err := scanner.Run(context.Background(), scanner.Params{
		Config:       cfg,
		GitHub:       svc2,
		Stdout:       new(bytes.Buffer),
		Stderr:       new(bytes.Buffer),
		GracefulStop: graceful,
		Now:          fixedNow,
	}); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}

	data, err := os.ReadFile(cfg.OutputFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if bytes.Count(data, []byte(`"run_id"`)) != 2 {
		t.Fatalf("output file missing replayed findings:\n%s", string(data))
	}
}

type mockGitHub struct {
	runs map[string][]ghclient.WorkflowRun
	logs map[int64][]detector.ExtractedLogFile
}

func (m *mockGitHub) ValidateToken(context.Context, bool) (ghclient.AuthInfo, error) {
	return ghclient.AuthInfo{}, nil
}

func (m *mockGitHub) ListOrgRepos(context.Context, string) ([]string, error) { return nil, nil }

func (m *mockGitHub) ListWorkflowRuns(_ context.Context, owner, repo string, _ time.Time, _ time.Time) ([]ghclient.WorkflowRun, error) {
	return append([]ghclient.WorkflowRun(nil), m.runs[owner+"/"+repo]...), nil
}

func (m *mockGitHub) DownloadRunLogs(_ context.Context, _, _ string, runID int64) ([]detector.ExtractedLogFile, error) {
	return append([]detector.ExtractedLogFile(nil), m.logs[runID]...), nil
}

func fixedNow() time.Time {
	return time.Date(2026, 5, 18, 16, 0, 0, 0, time.UTC)
}
