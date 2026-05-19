package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/model"
)

type WorkflowRecord struct {
	Org          string
	Repo         string
	WorkflowName string
	RunID        int64
	RunURL       string
	CreatedAt    time.Time
}

type Store struct {
	path  string
	now   func() time.Time
	mu    sync.Mutex
	state config.State
}

func Open(path string, manifestHash string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			ts := now().UTC()
			return &Store{
				path: path,
				now:  now,
				state: config.State{
					Version:        config.StateVersion,
					ManifestHash:   manifestHash,
					CreatedAt:      ts,
					UpdatedAt:      ts,
					RepoStates:     map[string]config.RepoState{},
					WorkflowStates: map[string]config.WorkflowState{},
					Findings:       []model.Finding{},
					SuppressedRuns: []model.SuppressedRun{},
				},
			}, nil
		}
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}

	var st config.State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("decode state %s: %w", path, err)
	}
	if st.ManifestHash != manifestHash {
		return nil, fmt.Errorf("manifest/state mismatch")
	}
	if st.RepoStates == nil {
		st.RepoStates = map[string]config.RepoState{}
	}
	if st.WorkflowStates == nil {
		st.WorkflowStates = map[string]config.WorkflowState{}
	}

	return &Store{path: path, now: now, state: st}, nil
}

func (s *Store) Snapshot() config.State {
	s.mu.Lock()
	defer s.mu.Unlock()

	return cloneState(s.state)
}

func (s *Store) HasWorkflowStates() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.state.WorkflowStates) > 0
}

func (s *Store) EnsureRepo(repo, org string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.state.RepoStates[repo]; ok {
		return nil
	}
	s.state.RepoStates[repo] = config.RepoState{
		Org:       org,
		Repo:      repo,
		Status:    config.RepoStatusPending,
		UpdatedAt: s.now().UTC(),
	}
	return s.saveLocked()
}

func (s *Store) SetRepoEnumeration(repo, org string, count int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	repoState := s.state.RepoStates[repo]
	repoState.Org = org
	repoState.Repo = repo
	repoState.EnumeratedWorkflows = count
	repoState.Status = config.RepoStatusPending
	repoState.UpdatedAt = s.now().UTC()
	s.state.RepoStates[repo] = repoState
	return s.saveLocked()
}

func (s *Store) SetRepoFailed(repo, org string, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	repoState := s.state.RepoStates[repo]
	repoState.Org = org
	repoState.Repo = repo
	repoState.Status = config.RepoStatusFailed
	repoState.LastError = err.Error()
	repoState.UpdatedAt = s.now().UTC()
	s.state.RepoStates[repo] = repoState
	return s.saveLocked()
}

func (s *Store) PersistWorkflowList(records []WorkflowRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range records {
		key := workflowKey(record.Repo, record.RunID)
		if _, ok := s.state.WorkflowStates[key]; ok {
			continue
		}
		s.state.WorkflowStates[key] = config.WorkflowState{
			Org:          record.Org,
			Repo:         record.Repo,
			WorkflowName: record.WorkflowName,
			RunID:        record.RunID,
			RunURL:       record.RunURL,
			CreatedAt:    record.CreatedAt.UTC(),
			Status:       config.WorkflowStatusPending,
			UpdatedAt:    s.now().UTC(),
		}
	}
	return s.saveLocked()
}

func (s *Store) RemainingWorkflows(repoOrder []string, maxRuns int) []WorkflowRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	order := make(map[string]int, len(repoOrder))
	for i, repo := range repoOrder {
		order[repo] = i
	}

	out := make([]WorkflowRecord, 0, len(s.state.WorkflowStates))
	for _, wf := range s.state.WorkflowStates {
		if wf.Status == config.WorkflowStatusCompleted {
			continue
		}
		out = append(out, WorkflowRecord{
			Org:          wf.Org,
			Repo:         wf.Repo,
			WorkflowName: wf.WorkflowName,
			RunID:        wf.RunID,
			RunURL:       wf.RunURL,
			CreatedAt:    wf.CreatedAt.UTC(),
		})
	}

	slices.SortStableFunc(out, func(a, b WorkflowRecord) int {
		if order[a.Repo] != order[b.Repo] {
			if order[a.Repo] < order[b.Repo] {
				return -1
			}
			return 1
		}
		if a.CreatedAt.Equal(b.CreatedAt) {
			switch {
			case a.RunID > b.RunID:
				return -1
			case a.RunID < b.RunID:
				return 1
			default:
				return 0
			}
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		return 1
	})

	if maxRuns > 0 && len(out) > maxRuns {
		out = out[:maxRuns]
	}

	return out
}

func (s *Store) MarkWorkflowInProgress(repo string, runID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := workflowKey(repo, runID)
	workflow := s.state.WorkflowStates[key]
	workflow.Status = config.WorkflowStatusInProgress
	workflow.LastError = ""
	workflow.UpdatedAt = s.now().UTC()
	s.state.WorkflowStates[key] = workflow

	repoState := s.state.RepoStates[repo]
	repoState.Status = config.RepoStatusInProgress
	repoState.UpdatedAt = s.now().UTC()
	s.state.RepoStates[repo] = repoState

	return s.saveLocked()
}

func (s *Store) MarkWorkflowFailed(repo string, runID int64, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := workflowKey(repo, runID)
	workflow := s.state.WorkflowStates[key]
	workflow.Status = config.WorkflowStatusFailed
	workflow.LastError = err.Error()
	workflow.UpdatedAt = s.now().UTC()
	s.state.WorkflowStates[key] = workflow
	return s.saveLocked()
}

func (s *Store) RecordCompleted(record WorkflowRecord, finding *model.Finding, suppressedRun *model.SuppressedRun, suppressedCount int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := workflowKey(record.Repo, record.RunID)
	workflow := s.state.WorkflowStates[key]
	workflow.Status = config.WorkflowStatusCompleted
	workflow.LastError = ""
	workflow.UpdatedAt = s.now().UTC()
	s.state.WorkflowStates[key] = workflow

	repoState := s.state.RepoStates[record.Repo]
	repoState.CompletedWorkflows++
	repoState.UpdatedAt = s.now().UTC()
	s.state.RepoStates[record.Repo] = repoState

	s.state.TotalRunsScanned++
	s.state.TotalSuppressedMatches += suppressedCount
	setMinTime(&s.state.FirstScannedRunAt, record.CreatedAt.UTC())
	setMaxTime(&s.state.LastScannedRunAt, record.CreatedAt.UTC())
	if finding != nil {
		s.state.Findings = append(s.state.Findings, *finding)
	}
	if suppressedRun != nil {
		s.state.SuppressedRuns = append(s.state.SuppressedRuns, *suppressedRun)
	}
	return s.saveLocked()
}

func (s *Store) FinalizeRepoStatuses() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for repo, repoState := range s.state.RepoStates {
		var total int
		var completed int
		var failed bool
		var inProgress bool
		for _, wf := range s.state.WorkflowStates {
			if wf.Repo != repo {
				continue
			}
			total++
			switch wf.Status {
			case config.WorkflowStatusCompleted:
				completed++
			case config.WorkflowStatusFailed:
				failed = true
			case config.WorkflowStatusInProgress:
				inProgress = true
			}
		}
		switch {
		case total == 0 && repoState.Status != config.RepoStatusFailed:
			repoState.Status = config.RepoStatusCompleted
		case completed == total && total > 0:
			repoState.Status = config.RepoStatusCompleted
		case failed:
			repoState.Status = config.RepoStatusFailed
		case inProgress || completed > 0:
			repoState.Status = config.RepoStatusInProgress
		default:
			repoState.Status = config.RepoStatusPending
		}
		repoState.UpdatedAt = s.now().UTC()
		s.state.RepoStates[repo] = repoState
	}
	return s.saveLocked()
}

func (s *Store) AnyIncomplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, repoState := range s.state.RepoStates {
		if repoState.Status != config.RepoStatusCompleted {
			return true
		}
	}
	for _, workflow := range s.state.WorkflowStates {
		if workflow.Status != config.WorkflowStatusCompleted {
			return true
		}
	}
	return false
}

func workflowKey(repo string, runID int64) string {
	return fmt.Sprintf("%s#%d", repo, runID)
}

func (s *Store) saveLocked() error {
	s.state.UpdatedAt = s.now().UTC()
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(s.path), "actologger-state-*.json")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}

func cloneState(in config.State) config.State {
	out := in
	if in.FirstScannedRunAt != nil {
		t := *in.FirstScannedRunAt
		out.FirstScannedRunAt = &t
	}
	if in.LastScannedRunAt != nil {
		t := *in.LastScannedRunAt
		out.LastScannedRunAt = &t
	}
	out.RepoStates = make(map[string]config.RepoState, len(in.RepoStates))
	for k, v := range in.RepoStates {
		out.RepoStates[k] = v
	}
	out.WorkflowStates = make(map[string]config.WorkflowState, len(in.WorkflowStates))
	for k, v := range in.WorkflowStates {
		out.WorkflowStates[k] = v
	}
	out.Findings = append([]model.Finding(nil), in.Findings...)
	out.SuppressedRuns = append([]model.SuppressedRun(nil), in.SuppressedRuns...)
	return out
}

func setMinTime(dst **time.Time, value time.Time) {
	if *dst == nil || value.Before((**dst)) {
		v := value
		*dst = &v
	}
}

func setMaxTime(dst **time.Time, value time.Time) {
	if *dst == nil || value.After((**dst)) {
		v := value
		*dst = &v
	}
}
