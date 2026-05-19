# actologger

`actologger` scans GitHub Actions workflow run logs for compromise indicators tied to supported supply-chain incidents.

Today it supports these detectors:

- `trivy`
- `mini-shai-hulud`

It authenticates to GitHub, resolves repositories from explicit `--repo` targets and/or `--org` expansion, downloads workflow logs in a time window, matches detector indicators, and emits findings as JSON or CSV.

## What it does

- Scans GitHub Actions workflow run logs within a requested time range
- Supports direct repo targeting, org expansion, and manifest-driven scans
- Streams findings to an output file while the scan is still running
- Can persist scan state for resumable long-running scans
- Can optionally save workflow logs for findings or for every scanned run
- Handles graceful shutdown on first interrupt and forced cancellation on second interrupt

## Requirements

- Go toolchain compatible with `go.mod`
- A GitHub token in `GITHUB_TOKEN`

`actologger` does **not** accept `--token`; credentials must be provided through the environment.

## Build

```bash
make build
```

Or:

```bash
go build -o actologger .
```

## Quick start

Validate auth and configuration:

```bash
export GITHUB_TOKEN=your-token
go run . --repo navikt/tpt-backend --dry-run
```

Scan a single repository and write JSON results to a file:

```bash
export GITHUB_TOKEN=your-token
go run . \
  --repo navikt/tpt-backend \
  --detector mini-shai-hulud \
  --since 2026-05-11T00:00:00Z \
  --until 2026-05-18T23:59:59Z \
  --output results.json
```

Scan an organization and save matching logs:

```bash
export GITHUB_TOKEN=your-token
go run . \
  --org navikt \
  --detector trivy \
  --output results.json \
  --log-dir navikt-scan
```

Resume a larger scan with manifest and state files:

```bash
export GITHUB_TOKEN=your-token
go run . \
  --manifest-file manifest.json \
  --state-file state.json \
  --output results.json
```

## Output behavior

- Operational logs, progress, and the final scan summary are written to `stderr`
- Structured results are written to `stdout` unless `--output` is set
- `--format` supports `json` and `csv`
- When `--output` is set, findings are appended as they are discovered so long scans keep durable results on disk

JSON results include scan metadata, findings, suppressed runs, and repo/run counters. CSV output contains one row per finding.

## Common flags

| Flag | Description |
| --- | --- |
| `--repo` | Scan one or more repositories in `owner/repo` format |
| `--org` | Expand an organization into repositories before scanning |
| `--detector` | Detector to run: `trivy` or `mini-shai-hulud` |
| `--since`, `--until` | RFC3339 scan window |
| `--output` | Write structured output to a file instead of stdout |
| `--format` | Output format: `json` or `csv` |
| `--max-runs` | Limit how many workflow runs are scanned |
| `--workers` | Control scan concurrency |
| `--dry-run` | Validate token access and configuration without scanning |
| `--verbose` | Enable debug logging |
| `--log-dir` | Save downloaded logs for findings |
| `--log-dir-split` | Save one file per extracted log entry |
| `--log-dir-all` | Save logs for every scanned run, not only findings |
| `--manifest-file` | Write or reuse a manifest describing the scan scope |
| `--state-file` | Persist workflow state for resumable scans; requires `--manifest-file` |

## Project layout

```text
.
├── cmd/actologger/        # Alternate CLI entrypoint
├── internal/app/          # Application bootstrap and lifecycle
├── internal/cli/          # Flag parsing and config resolution
├── internal/config/       # Manifest and state models
├── internal/detector/     # Detector metadata and matching rules
├── internal/github/       # GitHub API client
├── internal/output/       # Progress, summaries, JSON/CSV sinks
├── internal/scanner/      # Scan orchestration
└── internal/state/        # Persistent resumable scan state
```

## Common tasks

```bash
make build
make test
make tidy
make run
```
