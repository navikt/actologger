package output

import (
	"fmt"
	"io"

	"github.com/navikt/actologger/internal/model"
)

func PrintSummary(w io.Writer, result model.ScanResult) {
	fmt.Fprintf(w, "detector: %s\n", result.Detector)
	fmt.Fprintf(w, "scanned at: %s\n", result.ScannedAt.UTC().Format(timeFormat))
	fmt.Fprintf(w, "requested since: %s\n", result.RequestedSince.UTC().Format(timeFormat))
	fmt.Fprintf(w, "requested until: %s\n", result.RequestedUntil.UTC().Format(timeFormat))
	fmt.Fprintf(w, "repos scanned: %d\n", result.TotalRepos)
	fmt.Fprintf(w, "workflows scanned: %d\n", result.TotalRunsScanned)
	fmt.Fprintf(w, "findings: %d\n", result.TotalFindings)
	if result.Partial {
		fmt.Fprintln(w, "partial: true")
	}
	if result.FirstScannedRunAt != nil {
		fmt.Fprintf(w, "first scanned workflow: %s\n", result.FirstScannedRunAt.UTC().Format(timeFormat))
	}
	if result.LastScannedRunAt != nil {
		fmt.Fprintf(w, "last scanned workflow: %s\n", result.LastScannedRunAt.UTC().Format(timeFormat))
	}
	if result.TotalSuppressedMatches > 0 {
		fmt.Fprintf(w, "suppressed matches: %d\n", result.TotalSuppressedMatches)
	}
	fmt.Fprintf(w, "completed repos: %d\n", result.CompletedRepos)
	fmt.Fprintf(w, "pending repos: %d\n", result.PendingRepos)
	fmt.Fprintf(w, "failed repos: %d\n", result.FailedRepos)
}
