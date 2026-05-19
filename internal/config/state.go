package config

import (
	"time"

	"github.com/navikt/actologger/internal/model"
)

const StateVersion = 1

type WorkflowStatus string

const (
	WorkflowStatusPending    WorkflowStatus = "pending"
	WorkflowStatusInProgress WorkflowStatus = "in_progress"
	WorkflowStatusCompleted  WorkflowStatus = "completed"
	WorkflowStatusFailed     WorkflowStatus = "failed"
)

type RepoStatus string

const (
	RepoStatusPending    RepoStatus = "pending"
	RepoStatusInProgress RepoStatus = "in_progress"
	RepoStatusCompleted  RepoStatus = "completed"
	RepoStatusFailed     RepoStatus = "failed"
)

type State struct {
	Version                int                      `json:"version"`
	ManifestHash           string                   `json:"manifest_hash"`
	CreatedAt              time.Time                `json:"created_at"`
	UpdatedAt              time.Time                `json:"updated_at"`
	TotalRunsScanned       int                      `json:"total_runs_scanned"`
	TotalSuppressedMatches int                      `json:"total_suppressed_matches"`
	FirstScannedRunAt      *time.Time               `json:"first_scanned_run_at"`
	LastScannedRunAt       *time.Time               `json:"last_scanned_run_at"`
	RepoStates             map[string]RepoState     `json:"repo_states"`
	WorkflowStates         map[string]WorkflowState `json:"workflow_states"`
	Findings               []model.Finding          `json:"findings"`
	SuppressedRuns         []model.SuppressedRun    `json:"suppressed_runs"`
}

type RepoState struct {
	Org                 string     `json:"org"`
	Repo                string     `json:"repo"`
	Status              RepoStatus `json:"status"`
	EnumeratedWorkflows int        `json:"enumerated_workflows"`
	CompletedWorkflows  int        `json:"completed_workflows"`
	LastError           string     `json:"last_error"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type WorkflowState struct {
	Org          string         `json:"org"`
	Repo         string         `json:"repo"`
	WorkflowName string         `json:"workflow_name"`
	RunID        int64          `json:"run_id"`
	RunURL       string         `json:"run_url"`
	CreatedAt    time.Time      `json:"created_at"`
	Status       WorkflowStatus `json:"status"`
	LastError    string         `json:"last_error"`
	UpdatedAt    time.Time      `json:"updated_at"`
}
