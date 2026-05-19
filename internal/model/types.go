package model

import "time"

type Match struct {
	Pattern    string `json:"pattern"`
	Kind       string `json:"kind"`
	Confidence string `json:"confidence"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	FileLine   int    `json:"file_line"`
	Snippet    string `json:"snippet"`
}

type SuppressedMatch struct {
	Pattern  string `json:"pattern"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	FileLine int    `json:"file_line"`
	Reason   string `json:"reason"`
	Snippet  string `json:"snippet"`
}

type Finding struct {
	Org               string            `json:"org"`
	Repo              string            `json:"repo"`
	WorkflowName      string            `json:"workflow_name"`
	RunID             int64             `json:"run_id"`
	RunURL            string            `json:"run_url"`
	TriggeredAt       time.Time         `json:"triggered_at"`
	Matches           []Match           `json:"matches"`
	SuppressedMatches []SuppressedMatch `json:"suppressed_matches"`
	MatchSummary      string            `json:"match_summary"`
}

type SuppressedRun struct {
	Org               string            `json:"org"`
	Repo              string            `json:"repo"`
	WorkflowName      string            `json:"workflow_name"`
	RunID             int64             `json:"run_id"`
	RunURL            string            `json:"run_url"`
	TriggeredAt       time.Time         `json:"triggered_at"`
	SuppressedMatches []SuppressedMatch `json:"suppressed_matches"`
	SuppressedSummary string            `json:"suppressed_summary"`
}

type ScanResult struct {
	Partial                bool            `json:"partial"`
	Detector               string          `json:"detector"`
	ScannedAt              time.Time       `json:"scanned_at"`
	RequestedSince         time.Time       `json:"requested_since"`
	RequestedUntil         time.Time       `json:"requested_until"`
	FirstScannedRunAt      *time.Time      `json:"first_scanned_run_at"`
	LastScannedRunAt       *time.Time      `json:"last_scanned_run_at"`
	TotalRepos             int             `json:"total_repos"`
	TotalRunsScanned       int             `json:"total_runs_scanned"`
	TotalFindings          int             `json:"total_findings"`
	TotalSuppressedMatches int             `json:"total_suppressed_matches"`
	CompletedRepos         int             `json:"completed_repos"`
	PendingRepos           int             `json:"pending_repos"`
	FailedRepos            int             `json:"failed_repos"`
	Findings               []Finding       `json:"findings"`
	SuppressedRuns         []SuppressedRun `json:"suppressed_runs"`
}
