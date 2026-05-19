package output_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/model"
	"github.com/navikt/actologger/internal/output"
)

func TestJSONSinkReplayAndCloseProducesValidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	header := model.ScanResult{
		Detector:       "trivy",
		ScannedAt:      time.Date(2026, 5, 18, 16, 0, 0, 0, time.UTC),
		RequestedSince: time.Date(2026, 5, 18, 15, 0, 0, 0, time.UTC),
		RequestedUntil: time.Date(2026, 5, 18, 16, 0, 0, 0, time.UTC),
	}
	initial := []model.Finding{{Org: "navikt", Repo: "navikt/a", WorkflowName: "CI", RunID: 1, MatchSummary: "x", TriggeredAt: header.ScannedAt}}

	sink, err := output.NewSink(path, config.FormatJSON, header, initial)
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	if err := sink.EmitFinding(model.Finding{Org: "navikt", Repo: "navikt/b", WorkflowName: "Build", RunID: 2, MatchSummary: "y", TriggeredAt: header.ScannedAt}); err != nil {
		t.Fatalf("EmitFinding() error = %v", err)
	}
	header.Findings = append(initial, model.Finding{Org: "navikt", Repo: "navikt/b", WorkflowName: "Build", RunID: 2, MatchSummary: "y", TriggeredAt: header.ScannedAt})
	header.TotalFindings = 2
	if err := sink.Close(header); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v\n%s", err, string(data))
	}
}

func TestCSVSinkWritesRows(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "findings.csv")
	header := model.ScanResult{}
	sink, err := output.NewSink(path, config.FormatCSV, header, nil)
	if err != nil {
		t.Fatalf("NewSink() error = %v", err)
	}
	if err := sink.EmitFinding(model.Finding{Org: "navikt", Repo: "navikt/a", WorkflowName: "CI", RunID: 1, MatchSummary: "a; b", TriggeredAt: time.Date(2026, 5, 18, 16, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("EmitFinding() error = %v", err)
	}
	if err := sink.Close(model.ScanResult{}); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "org,repo,workflow_name,run_id,run_url,triggered_at,matches") {
		t.Fatalf("CSV header missing:\n%s", string(data))
	}
}
