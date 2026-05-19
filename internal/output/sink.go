package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/model"
)

type Sink interface {
	EmitFinding(model.Finding) error
	Close(model.ScanResult) error
}

func NewSink(path string, format config.OutputFormat, cfg model.ScanResult, initial []model.Finding) (Sink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}

	switch format {
	case config.FormatJSON:
		sink := &jsonSink{
			file:   file,
			writer: bufio.NewWriter(file),
			header: cfg,
			first:  true,
		}
		if err := sink.open(); err != nil {
			_ = file.Close()
			return nil, err
		}
		for _, finding := range initial {
			if err := sink.EmitFinding(finding); err != nil {
				_ = file.Close()
				return nil, err
			}
		}
		return sink, nil
	case config.FormatCSV:
		sink := &csvSink{file: file}
		sink.writer = bufio.NewWriter(file)
		sink.csv = csv.NewWriter(sink.writer)
		if err := sink.csv.Write([]string{"org", "repo", "workflow_name", "run_id", "run_url", "triggered_at", "matches"}); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
		sink.csv.Flush()
		if err := sink.csv.Error(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("flush CSV header: %w", err)
		}
		if err := sink.writer.Flush(); err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("flush CSV writer: %w", err)
		}
		for _, finding := range initial {
			if err := sink.EmitFinding(finding); err != nil {
				_ = file.Close()
				return nil, err
			}
		}
		return sink, nil
	default:
		_ = file.Close()
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}

type jsonSink struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
	header model.ScanResult
	first  bool
	closed bool
}

func (s *jsonSink) open() error {
	prefix, err := json.Marshal(struct {
		Detector       string `json:"detector"`
		ScannedAt      any    `json:"scanned_at"`
		RequestedSince any    `json:"requested_since"`
		RequestedUntil any    `json:"requested_until"`
	}{
		Detector:       s.header.Detector,
		ScannedAt:      s.header.ScannedAt,
		RequestedSince: s.header.RequestedSince,
		RequestedUntil: s.header.RequestedUntil,
	})
	if err != nil {
		return fmt.Errorf("marshal JSON sink header: %w", err)
	}
	body := string(prefix)
	body = body[:len(body)-1] + `,"findings":[`
	if _, err := s.writer.WriteString(body); err != nil {
		return fmt.Errorf("write JSON sink header: %w", err)
	}
	return s.writer.Flush()
}

func (s *jsonSink) EmitFinding(finding model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("emit finding on closed JSON sink")
	}

	if !s.first {
		if _, err := s.writer.WriteString(","); err != nil {
			return fmt.Errorf("write JSON finding separator: %w", err)
		}
	}
	data, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("marshal JSON finding: %w", err)
	}
	if _, err := s.writer.Write(data); err != nil {
		return fmt.Errorf("write JSON finding: %w", err)
	}
	s.first = false
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush JSON sink: %w", err)
	}
	return nil
}

func (s *jsonSink) Close(result model.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	tail, err := json.Marshal(struct {
		SuppressedRuns         []model.SuppressedRun `json:"suppressed_runs"`
		Partial                bool                  `json:"partial"`
		FirstScannedRunAt      *time.Time            `json:"first_scanned_run_at"`
		LastScannedRunAt       *time.Time            `json:"last_scanned_run_at"`
		TotalRepos             int                   `json:"total_repos"`
		TotalRunsScanned       int                   `json:"total_runs_scanned"`
		TotalFindings          int                   `json:"total_findings"`
		TotalSuppressedMatches int                   `json:"total_suppressed_matches"`
		CompletedRepos         int                   `json:"completed_repos"`
		PendingRepos           int                   `json:"pending_repos"`
		FailedRepos            int                   `json:"failed_repos"`
	}{
		SuppressedRuns:         result.SuppressedRuns,
		Partial:                result.Partial,
		FirstScannedRunAt:      result.FirstScannedRunAt,
		LastScannedRunAt:       result.LastScannedRunAt,
		TotalRepos:             result.TotalRepos,
		TotalRunsScanned:       result.TotalRunsScanned,
		TotalFindings:          result.TotalFindings,
		TotalSuppressedMatches: result.TotalSuppressedMatches,
		CompletedRepos:         result.CompletedRepos,
		PendingRepos:           result.PendingRepos,
		FailedRepos:            result.FailedRepos,
	})
	if err != nil {
		return fmt.Errorf("marshal JSON sink footer: %w", err)
	}
	body := string(tail)
	body = `],` + body[1:]
	if _, err := s.writer.WriteString(body); err != nil {
		return fmt.Errorf("write JSON sink footer: %w", err)
	}
	if _, err := s.writer.WriteString("\n"); err != nil {
		return fmt.Errorf("write JSON sink newline: %w", err)
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush JSON sink close: %w", err)
	}
	s.closed = true
	return s.file.Close()
}

type csvSink struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
	csv    *csv.Writer
	closed bool
}

func (s *csvSink) EmitFinding(finding model.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("emit finding on closed CSV sink")
	}
	if err := s.csv.Write([]string{
		finding.Org,
		finding.Repo,
		finding.WorkflowName,
		strconv.FormatInt(finding.RunID, 10),
		finding.RunURL,
		finding.TriggeredAt.UTC().Format(timeFormat),
		finding.MatchSummary,
	}); err != nil {
		return fmt.Errorf("write CSV finding: %w", err)
	}
	s.csv.Flush()
	if err := s.csv.Error(); err != nil {
		return fmt.Errorf("flush CSV finding: %w", err)
	}
	return s.writer.Flush()
}

func (s *csvSink) Close(_ model.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.csv.Flush()
	if err := s.csv.Error(); err != nil {
		return fmt.Errorf("flush CSV sink close: %w", err)
	}
	if err := s.writer.Flush(); err != nil {
		return fmt.Errorf("flush CSV writer close: %w", err)
	}
	s.closed = true
	return s.file.Close()
}
