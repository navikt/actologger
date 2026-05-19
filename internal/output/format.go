package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/model"
)

func FormatResult(format config.OutputFormat, result model.ScanResult) ([]byte, error) {
	switch format {
	case config.FormatJSON:
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal JSON result: %w", err)
		}
		return append(data, '\n'), nil
	case config.FormatCSV:
		var buf bytes.Buffer
		writer := csv.NewWriter(&buf)
		if err := writer.Write([]string{"org", "repo", "workflow_name", "run_id", "run_url", "triggered_at", "matches"}); err != nil {
			return nil, fmt.Errorf("write CSV header: %w", err)
		}
		for _, finding := range result.Findings {
			record := []string{
				finding.Org,
				finding.Repo,
				finding.WorkflowName,
				fmt.Sprintf("%d", finding.RunID),
				finding.RunURL,
				finding.TriggeredAt.UTC().Format(timeFormat),
				finding.MatchSummary,
			}
			if err := writer.Write(record); err != nil {
				return nil, fmt.Errorf("write CSV record: %w", err)
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return nil, fmt.Errorf("flush CSV output: %w", err)
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
}

const timeFormat = "2006-01-02T15:04:05Z07:00"
