package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/detector"
	ghclient "github.com/navikt/actologger/internal/github"
	"github.com/navikt/actologger/internal/model"
	"github.com/navikt/actologger/internal/output"
	"github.com/navikt/actologger/internal/state"
)

type GitHubService interface {
	ValidateToken(ctx context.Context, needsOrgScope bool) (ghclient.AuthInfo, error)
	ListOrgRepos(ctx context.Context, org string) ([]string, error)
	ListWorkflowRuns(ctx context.Context, owner, repo string, since, until time.Time) ([]ghclient.WorkflowRun, error)
	DownloadRunLogs(ctx context.Context, owner, repo string, runID int64) ([]detector.ExtractedLogFile, error)
}

type Params struct {
	Config       config.Config
	Logger       *slog.Logger
	Stdout       io.Writer
	Stderr       io.Writer
	GitHub       GitHubService
	GracefulStop <-chan struct{}
	Now          func() time.Time
}

type runTarget struct {
	Org      string
	Repo     string
	Owner    string
	RepoName string
	RunID    int64
	RunName  string
	RunURL   string
	RunTime  time.Time
}

type repoStatus string

const (
	repoPending    repoStatus = "pending"
	repoInProgress repoStatus = "in_progress"
	repoCompleted  repoStatus = "completed"
	repoFailed     repoStatus = "failed"
)

func Run(ctx context.Context, params Params) (model.ScanResult, error) {
	now := params.Now
	if now == nil {
		now = time.Now
	}
	log := params.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(params.Stderr, nil))
	}

	auth, err := params.GitHub.ValidateToken(ctx, len(params.Config.Orgs) > 0)
	if err != nil {
		if isGracefulStop(err) {
			return model.ScanResult{
				Partial:        true,
				Detector:       params.Config.Detector,
				ScannedAt:      now().UTC(),
				RequestedSince: params.Config.Since.UTC(),
				RequestedUntil: params.Config.Until.UTC(),
			}, nil
		}
		return model.ScanResult{}, err
	}
	if auth.Username != "" {
		log.Info("authenticated to GitHub", "user", auth.Username)
	}
	log.Info("GitHub rate limit", "limit", auth.RateLimit, "remaining", auth.RateRemaining, "reset", auth.RateReset.UTC().Format(time.RFC3339))

	if params.Config.DryRun {
		return model.ScanResult{}, nil
	}

	def, ok := detector.Lookup(params.Config.Detector)
	if !ok {
		return model.ScanResult{}, fmt.Errorf("unknown detector %q", params.Config.Detector)
	}

	resolvedRepos, manifest, err := resolveManifestAndTargets(ctx, params, log)
	if err != nil {
		if isGracefulStop(err) {
			return model.ScanResult{
				Partial:        true,
				Detector:       params.Config.Detector,
				ScannedAt:      now().UTC(),
				RequestedSince: params.Config.Since.UTC(),
				RequestedUntil: params.Config.Until.UTC(),
			}, nil
		}
		return model.ScanResult{}, err
	}
	progress := output.NewProgress(params.Stderr, len(resolvedRepos), params.Config.Workers)
	progress.Start()
	defer progress.Stop()
	if client, ok := params.GitHub.(*ghclient.Client); ok {
		client.OnRateLimit = func(event ghclient.RateLimitEvent) {
			if !event.Sleeping {
				progress.SetRateLimitMessage("")
				return
			}
			progress.SetRateLimitMessage(fmt.Sprintf("remaining=%d reset=%s", event.Remaining, event.ResetAt.UTC().Format(time.RFC3339)))
		}
	}

	var store *state.Store
	var initialFindings []model.Finding
	var initialSuppressed []model.SuppressedRun
	if params.Config.StateFile != "" {
		hash, err := manifest.CanonicalHash()
		if err != nil {
			return model.ScanResult{}, fmt.Errorf("hash manifest: %w", err)
		}
		store, err = state.Open(params.Config.StateFile, hash, now)
		if err != nil {
			return model.ScanResult{}, err
		}
		snapshot := store.Snapshot()
		initialFindings = snapshot.Findings
		initialSuppressed = snapshot.SuppressedRuns
	}

	resultHeader := model.ScanResult{
		Detector:       params.Config.Detector,
		ScannedAt:      now().UTC(),
		RequestedSince: params.Config.Since.UTC(),
		RequestedUntil: params.Config.Until.UTC(),
		Findings:       append([]model.Finding(nil), initialFindings...),
		SuppressedRuns: append([]model.SuppressedRun(nil), initialSuppressed...),
	}

	var sink output.Sink
	if params.Config.OutputFile != "" {
		sink, err = output.NewSink(params.Config.OutputFile, params.Config.Format, resultHeader, initialFindings)
		if err != nil {
			return model.ScanResult{}, err
		}
		defer func() {
			if sink != nil {
				_ = sink.Close(resultHeader)
			}
		}()
	}

	worklist, repoStates, err := enumerateRuns(ctx, params, log, progress, resolvedRepos, store)
	if err != nil {
		if isGracefulStop(err) {
			result := model.ScanResult{
				Partial:        true,
				Detector:       params.Config.Detector,
				ScannedAt:      now().UTC(),
				RequestedSince: params.Config.Since.UTC(),
				RequestedUntil: params.Config.Until.UTC(),
				TotalRepos:     len(resolvedRepos),
			}
			if store != nil {
				snapshot := store.Snapshot()
				result.TotalRunsScanned = snapshot.TotalRunsScanned
				result.TotalSuppressedMatches = snapshot.TotalSuppressedMatches
				result.FirstScannedRunAt = snapshot.FirstScannedRunAt
				result.LastScannedRunAt = snapshot.LastScannedRunAt
				result.Findings = snapshot.Findings
				result.SuppressedRuns = snapshot.SuppressedRuns
				result.TotalFindings = len(snapshot.Findings)
				result.CompletedRepos, result.PendingRepos, result.FailedRepos = summarizeRepoStates(nil, store)
			}
			return result, nil
		}
		return model.ScanResult{}, err
	}
	progress.SetKnownRuns(len(worklist))
	progress.BeginScanning()
	progress.SetStatus("scanning workflows")
	progress.Clear()
	log.Info("Scanning workflows")

	findings, suppressedRuns, stats, repoStates, err := scanRuns(ctx, params, def, worklist, repoStates, progress, sink, store)
	if err != nil {
		return model.ScanResult{}, err
	}

	result := model.ScanResult{
		Partial:                isPartial(ctx, params.GracefulStop, store),
		Detector:               params.Config.Detector,
		ScannedAt:              now().UTC(),
		RequestedSince:         params.Config.Since.UTC(),
		RequestedUntil:         params.Config.Until.UTC(),
		FirstScannedRunAt:      stats.FirstScannedRunAt,
		LastScannedRunAt:       stats.LastScannedRunAt,
		TotalRepos:             len(resolvedRepos),
		TotalRunsScanned:       stats.TotalRunsScanned,
		TotalFindings:          len(findings),
		TotalSuppressedMatches: stats.TotalSuppressedMatches,
		Findings:               findings,
		SuppressedRuns:         suppressedRuns,
	}
	result.CompletedRepos, result.PendingRepos, result.FailedRepos = summarizeRepoStates(repoStates, store)

	if sink != nil {
		if err := sink.Close(result); err != nil {
			return model.ScanResult{}, err
		}
		sink = nil
	}

	progress.Finish()
	output.PrintSummary(params.Stderr, result)
	return result, nil
}

func resolveManifestAndTargets(ctx context.Context, params Params, log *slog.Logger) ([]string, config.Manifest, error) {
	if params.Config.ExistingManifest != nil {
		return append([]string(nil), params.Config.ExistingManifest.Repos...), *params.Config.ExistingManifest, nil
	}

	seen := make(map[string]struct{})
	var repos []string
	for _, org := range params.Config.Orgs {
		if err := checkGraceful(ctx, params.GracefulStop); err != nil {
			return nil, config.Manifest{}, err
		}
		log.Info(fmt.Sprintf("Enumerating repos in %s", org))
		orgRepos, err := params.GitHub.ListOrgRepos(ctx, org)
		if err != nil {
			return nil, config.Manifest{}, err
		}
		log.Info(fmt.Sprintf("Enumerating %d repos in %s", len(orgRepos), org))
		for _, repo := range orgRepos {
			if _, ok := seen[repo]; ok {
				continue
			}
			seen[repo] = struct{}{}
			repos = append(repos, repo)
		}
	}
	for _, repo := range params.Config.Repos {
		if err := checkGraceful(ctx, params.GracefulStop); err != nil {
			return nil, config.Manifest{}, err
		}
		if _, ok := seen[repo]; ok {
			continue
		}
		seen[repo] = struct{}{}
		repos = append(repos, repo)
	}
	if len(repos) == 0 {
		return nil, config.Manifest{}, fmt.Errorf("manifest resolution produced zero repos")
	}

	manifest := config.Manifest{
		Version:        config.ManifestVersion,
		CreatedAt:      params.Now().UTC(),
		Detector:       params.Config.Detector,
		RequestedSince: params.Config.Since.UTC(),
		RequestedUntil: params.Config.Until.UTC(),
		Orgs:           append([]string(nil), params.Config.Orgs...),
		Repos:          append([]string(nil), repos...),
	}

	if params.Config.ManifestFile != "" {
		sorted := append([]string(nil), repos...)
		slices.Sort(sorted)
		manifest.Repos = sorted
		if err := config.SaveManifest(params.Config.ManifestFile, manifest); err != nil {
			return nil, config.Manifest{}, fmt.Errorf("write manifest: %w", err)
		}
	}

	return repos, manifest, nil
}

func enumerateRuns(ctx context.Context, params Params, log *slog.Logger, progress *output.Progress, repos []string, store *state.Store) ([]runTarget, map[string]repoStatus, error) {
	progress.SetStatus("discovering workflow runs")

	repoStates := make(map[string]repoStatus, len(repos))
	for _, repo := range repos {
		repoStates[repo] = repoPending
	}

	if store != nil {
		for _, repo := range repos {
			if err := checkGraceful(ctx, params.GracefulStop); err != nil {
				return nil, nil, err
			}
			org := strings.SplitN(repo, "/", 2)[0]
			if err := store.EnsureRepo(repo, org); err != nil {
				return nil, nil, err
			}
		}
	}

	if store != nil && store.HasWorkflowStates() {
		progress.Clear()
		log.Info("Enumerating workflows to scan")
		progress.SetEnumerationDone(len(repos))
		progress.SetKnownRuns(len(store.RemainingWorkflows(repos, params.Config.MaxRuns)))
		progress.SetStatus("reusing persisted workflow list from state")
		records := store.RemainingWorkflows(repos, params.Config.MaxRuns)
		targets := make([]runTarget, 0, len(records))
		for _, record := range records {
			owner, repoName := splitRepo(record.Repo)
			targets = append(targets, runTarget{
				Org:      record.Org,
				Repo:     record.Repo,
				Owner:    owner,
				RepoName: repoName,
				RunID:    record.RunID,
				RunName:  record.WorkflowName,
				RunURL:   record.RunURL,
				RunTime:  record.CreatedAt.UTC(),
			})
		}
		return targets, repoStates, nil
	}

	var allTargets []runTarget
	progress.Clear()
	log.Info("Enumerating workflows to scan")
	for i, repo := range repos {
		if err := checkGraceful(ctx, params.GracefulStop); err != nil {
			return nil, nil, err
		}
		progress.SetStatus(fmt.Sprintf("discovering workflow runs in %s", repo))
		owner, repoName := splitRepo(repo)
		runs, err := params.GitHub.ListWorkflowRuns(ctx, owner, repoName, params.Config.Since, params.Config.Until)
		if err != nil {
			if store != nil {
				if saveErr := store.SetRepoFailed(repo, owner, err); saveErr != nil {
					return nil, nil, saveErr
				}
				repoStates[repo] = repoFailed
				continue
			}
			progress.Clear()
			log.Warn("workflow enumeration failed", "repo", repo, "error", err)
			repoStates[repo] = repoFailed
			progress.SetEnumerationDone(i + 1)
			continue
		}
		if store != nil {
			if err := store.SetRepoEnumeration(repo, owner, len(runs)); err != nil {
				return nil, nil, err
			}
		}
		for _, run := range runs {
			allTargets = append(allTargets, runTarget{
				Org:      owner,
				Repo:     repo,
				Owner:    owner,
				RepoName: repoName,
				RunID:    run.ID,
				RunName:  run.Name,
				RunURL:   run.URL,
				RunTime:  run.CreatedAt.UTC(),
			})
		}
		progress.SetKnownRuns(len(allTargets))
		progress.SetEnumerationDone(i + 1)
	}

	if store != nil {
		records := make([]state.WorkflowRecord, 0, len(allTargets))
		for _, target := range allTargets {
			records = append(records, state.WorkflowRecord{
				Org:          target.Org,
				Repo:         target.Repo,
				WorkflowName: target.RunName,
				RunID:        target.RunID,
				RunURL:       target.RunURL,
				CreatedAt:    target.RunTime,
			})
		}
		if err := store.PersistWorkflowList(records); err != nil {
			return nil, nil, err
		}

		targets := make([]runTarget, 0, len(records))
		for _, record := range records {
			owner, repoName := splitRepo(record.Repo)
			targets = append(targets, runTarget{
				Org:      record.Org,
				Repo:     record.Repo,
				Owner:    owner,
				RepoName: repoName,
				RunID:    record.RunID,
				RunName:  record.WorkflowName,
				RunURL:   record.RunURL,
				RunTime:  record.CreatedAt.UTC(),
			})
		}
		if params.Config.MaxRuns > 0 && len(targets) > params.Config.MaxRuns {
			targets = targets[:params.Config.MaxRuns]
		}
		progress.SetEnumerationDone(len(repos))
		progress.SetKnownRuns(len(targets))
		progress.SetStatus("workflow enumeration complete")
		return targets, repoStates, nil
	}

	if params.Config.MaxRuns > 0 && len(allTargets) > params.Config.MaxRuns {
		allTargets = allTargets[:params.Config.MaxRuns]
	}
	progress.SetStatus("workflow enumeration complete")
	return allTargets, repoStates, nil
}

type scanStats struct {
	TotalRunsScanned       int
	TotalSuppressedMatches int
	FirstScannedRunAt      *time.Time
	LastScannedRunAt       *time.Time
}

type runResult struct {
	target          runTarget
	finding         *model.Finding
	suppressedRun   *model.SuppressedRun
	suppressedCount int
	saveWarning     error
	err             error
}

func scanRuns(ctx context.Context, params Params, def detector.Definition, targets []runTarget, repoStates map[string]repoStatus, progress *output.Progress, sink output.Sink, store *state.Store) ([]model.Finding, []model.SuppressedRun, scanStats, map[string]repoStatus, error) {
	jobs := make(chan runTarget)
	results := make(chan runResult, len(targets))

	var workerWG sync.WaitGroup
	for i := 0; i < params.Config.Workers; i++ {
		workerWG.Add(1)
		go func(slot int) {
			defer workerWG.Done()
			for target := range jobs {
				results <- processRun(ctx, params, def, progress, slot, target)
			}
			progress.UpdateSlot(slot, output.WorkerSlot{})
		}(i)
	}

	dispatched := 0
dispatchLoop:
	for _, target := range targets {
		select {
		case <-ctx.Done():
			break dispatchLoop
		case <-params.GracefulStop:
			break dispatchLoop
		default:
		}
		if store != nil {
			if err := store.MarkWorkflowInProgress(target.Repo, target.RunID); err != nil {
				return nil, nil, scanStats{}, nil, err
			}
		}
		repoStates[target.Repo] = repoInProgress
		jobs <- target
		dispatched++
	}
	close(jobs)

	go func() {
		workerWG.Wait()
		close(results)
	}()

	findings := make([]model.Finding, 0, dispatched)
	suppressedRuns := make([]model.SuppressedRun, 0, dispatched)
	stats := scanStats{}

	for result := range results {
		progress.IncrementDone()
		if result.saveWarning != nil {
			progress.Clear()
			params.Logger.Warn("save logs failed", "repo", result.target.Repo, "run_id", result.target.RunID, "error", result.saveWarning)
		}
		if result.err != nil {
			if store != nil {
				if err := store.MarkWorkflowFailed(result.target.Repo, result.target.RunID, result.err); err != nil {
					return nil, nil, scanStats{}, nil, err
				}
				repoStates[result.target.Repo] = repoFailed
				continue
			}
			progress.Clear()
			params.Logger.Warn("workflow scan failed", "repo", result.target.Repo, "run_id", result.target.RunID, "error", result.err)
			repoStates[result.target.Repo] = repoFailed
			continue
		}

		stats.TotalRunsScanned++
		stats.TotalSuppressedMatches += result.suppressedCount
		setMin(&stats.FirstScannedRunAt, result.target.RunTime)
		setMax(&stats.LastScannedRunAt, result.target.RunTime)
		repoStates[result.target.Repo] = repoCompleted

		if result.finding != nil {
			findings = append(findings, *result.finding)
			progress.IncrementFindings()
			progress.Notice(fmt.Sprintf("finding: repo=%s workflow=%s run=%d url=%s matches=%s", result.target.Repo, result.target.RunName, result.target.RunID, result.target.RunURL, result.finding.MatchSummary))
			if sink != nil {
				if err := sink.EmitFinding(*result.finding); err != nil {
					return nil, nil, scanStats{}, nil, err
				}
			}
		}
		if result.suppressedRun != nil {
			suppressedRuns = append(suppressedRuns, *result.suppressedRun)
		}
		if store != nil {
			record := state.WorkflowRecord{
				Org:          result.target.Org,
				Repo:         result.target.Repo,
				WorkflowName: result.target.RunName,
				RunID:        result.target.RunID,
				RunURL:       result.target.RunURL,
				CreatedAt:    result.target.RunTime,
			}
			if err := store.RecordCompleted(record, result.finding, result.suppressedRun, result.suppressedCount); err != nil {
				return nil, nil, scanStats{}, nil, err
			}
		}
	}

	if store != nil {
		if err := store.FinalizeRepoStatuses(); err != nil {
			return nil, nil, scanStats{}, nil, err
		}
	}

	if store != nil {
		snapshot := store.Snapshot()
		findings = snapshot.Findings
		suppressedRuns = snapshot.SuppressedRuns
		stats.TotalRunsScanned = snapshot.TotalRunsScanned
		stats.TotalSuppressedMatches = snapshot.TotalSuppressedMatches
		stats.FirstScannedRunAt = snapshot.FirstScannedRunAt
		stats.LastScannedRunAt = snapshot.LastScannedRunAt
	}

	return findings, suppressedRuns, stats, repoStates, nil
}

func processRun(ctx context.Context, params Params, def detector.Definition, progress *output.Progress, slot int, target runTarget) runResult {
	progress.UpdateSlot(slot, output.WorkerSlot{Repo: target.Repo, Workflow: target.RunName, RunID: target.RunID, RunURL: target.RunURL, Phase: output.WorkerDownloading})
	files, err := params.GitHub.DownloadRunLogs(ctx, target.Owner, target.RepoName, target.RunID)
	if err != nil {
		return runResult{target: target, err: err}
	}

	progress.UpdateSlot(slot, output.WorkerSlot{Repo: target.Repo, Workflow: target.RunName, RunID: target.RunID, RunURL: target.RunURL, Phase: output.WorkerMatching})
	scan := detector.Scan(def, files)
	progress.UpdateSlot(slot, output.WorkerSlot{Repo: target.Repo, Workflow: target.RunName, RunID: target.RunID, RunURL: target.RunURL, Phase: output.WorkerDone, FindingsCount: len(scan.Matches)})

	var finding *model.Finding
	if scan.IsFinding {
		finding = &model.Finding{
			Org:               target.Org,
			Repo:              target.Repo,
			WorkflowName:      target.RunName,
			RunID:             target.RunID,
			RunURL:            target.RunURL,
			TriggeredAt:       target.RunTime.UTC(),
			Matches:           scan.Matches,
			SuppressedMatches: scan.SuppressedMatches,
			MatchSummary:      scan.MatchSummary,
		}
	}

	var suppressedRun *model.SuppressedRun
	if len(scan.SuppressedMatches) > 0 {
		suppressedRun = &model.SuppressedRun{
			Org:               target.Org,
			Repo:              target.Repo,
			WorkflowName:      target.RunName,
			RunID:             target.RunID,
			RunURL:            target.RunURL,
			TriggeredAt:       target.RunTime.UTC(),
			SuppressedMatches: scan.SuppressedMatches,
			SuppressedSummary: scan.SuppressedSummary,
		}
	}

	var saveWarning error
	if params.Config.LogDir != "" && (scan.IsFinding || params.Config.SaveAllLogs) {
		saveWarning = saveLogs(params.Config, target, files)
	}

	return runResult{
		target:          target,
		finding:         finding,
		suppressedRun:   suppressedRun,
		suppressedCount: len(scan.SuppressedMatches),
		saveWarning:     saveWarning,
	}
}

func saveLogs(cfg config.Config, target runTarget, files []detector.ExtractedLogFile) error {
	if cfg.LogDirSplit {
		base := filepath.Join(cfg.LogDir, target.Owner, target.RepoName, fmt.Sprintf("%d", target.RunID))
		if err := os.MkdirAll(base, 0o755); err != nil {
			return fmt.Errorf("create split log dir: %w", err)
		}
		for _, file := range files {
			name := strings.ReplaceAll(file.Name, "/", "_")
			name = strings.ReplaceAll(name, string(os.PathSeparator), "_")
			if err := os.WriteFile(filepath.Join(base, name), []byte(file.Content), 0o644); err != nil {
				return fmt.Errorf("write split log file %s: %w", name, err)
			}
		}
		return nil
	}

	base := filepath.Join(cfg.LogDir, target.Owner, target.RepoName)
	if err := os.MkdirAll(base, 0o755); err != nil {
		return fmt.Errorf("create combined log dir: %w", err)
	}
	path := filepath.Join(base, fmt.Sprintf("%d.log", target.RunID))
	var b strings.Builder
	fmt.Fprintf(&b, "Repo: %s\n", target.Repo)
	fmt.Fprintf(&b, "Workflow: %s\n", target.RunName)
	fmt.Fprintf(&b, "Run ID: %d\n", target.RunID)
	fmt.Fprintf(&b, "Run URL: %s\n", target.RunURL)
	fmt.Fprintf(&b, "Triggered At: %s\n", target.RunTime.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "Log Files: %d\n", len(files))
	b.WriteString("\n")
	for i, file := range files {
		fmt.Fprintf(&b, "===== %s =====\n", file.Name)
		b.WriteString(file.Content)
		if !strings.HasSuffix(file.Content, "\n") {
			b.WriteString("\n")
		}
		if i+1 < len(files) {
			b.WriteString("\n")
		}
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("write combined log file: %w", err)
	}
	return nil
}

func splitRepo(repo string) (string, string) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 {
		return repo, ""
	}
	return parts[0], parts[1]
}

func summarizeRepoStates(repoStates map[string]repoStatus, store *state.Store) (completed, pending, failed int) {
	if store != nil {
		snapshot := store.Snapshot()
		for _, repo := range snapshot.RepoStates {
			switch repo.Status {
			case config.RepoStatusCompleted:
				completed++
			case config.RepoStatusFailed:
				failed++
			default:
				pending++
			}
		}
		return
	}
	for _, status := range repoStates {
		switch status {
		case repoCompleted:
			completed++
		case repoFailed:
			failed++
		default:
			pending++
		}
	}
	return
}

func isPartial(ctx context.Context, graceful <-chan struct{}, store *state.Store) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}
	select {
	case <-graceful:
		if store == nil {
			return true
		}
	default:
	}
	if store != nil {
		return store.AnyIncomplete()
	}
	return false
}

func checkGraceful(ctx context.Context, graceful <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	select {
	case <-graceful:
		return ghclient.ErrGracefulStop
	default:
		return nil
	}
}

func isGracefulStop(err error) bool {
	return err == ghclient.ErrGracefulStop
}

func setMin(dst **time.Time, value time.Time) {
	if *dst == nil || value.Before(**dst) {
		v := value
		*dst = &v
	}
}

func setMax(dst **time.Time, value time.Time) {
	if *dst == nil || value.After(**dst) {
		v := value
		*dst = &v
	}
}
