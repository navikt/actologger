package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/navikt/actologger/internal/config"
	"github.com/navikt/actologger/internal/detector"
)

type rawFlags struct {
	orgs         *stringListValue
	repos        *stringListValue
	since        string
	until        string
	output       string
	format       string
	detectorName string
	maxRuns      int
	workers      int
	dryRun       bool
	verbose      bool
	logDir       string
	logDirSplit  bool
	logDirAll    bool
	manifestFile string
	stateFile    string
}

func Parse(args []string, stderr io.Writer, getenv func(string) string, now func() time.Time) (config.Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if now == nil {
		now = time.Now
	}

	raw, err := parseFlags(args, stderr)
	if err != nil {
		return config.Config{}, err
	}

	manifest, err := loadManifest(raw.manifestFile)
	if err != nil {
		return config.Config{}, err
	}

	return buildConfig(raw, manifest, getenv, now)
}

func parseFlags(args []string, stderr io.Writer) (rawFlags, error) {
	orgs := newStringListValue()
	repos := newStringListValue()

	raw := rawFlags{
		orgs:         orgs,
		repos:        repos,
		format:       string(config.FormatJSON),
		detectorName: detector.NameTrivy,
		workers:      5,
	}

	fs := flag.NewFlagSet("actologger", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.Var(orgs, "org", "GitHub organization to scan")
	fs.Var(repos, "repo", "GitHub repository to scan in owner/repo format (alias: -r)")
	fs.StringVar(&raw.since, "since", "", "RFC3339 lower bound")
	fs.StringVar(&raw.until, "until", "", "RFC3339 upper bound")
	fs.StringVar(&raw.output, "output", "", "Output file path")
	fs.StringVar(&raw.format, "format", raw.format, "Output format: json or csv (alias: -f)")
	fs.StringVar(&raw.detectorName, "detector", raw.detectorName, "Detector to run")
	fs.IntVar(&raw.maxRuns, "max-runs", 0, "Maximum number of workflow runs to scan")
	fs.IntVar(&raw.workers, "workers", raw.workers, "Worker count (alias: -w)")
	fs.BoolVar(&raw.dryRun, "dry-run", false, "Validate configuration and exit")
	fs.BoolVar(&raw.verbose, "verbose", false, "Enable debug logging (alias: -v)")
	fs.StringVar(&raw.logDir, "log-dir", "", "Directory for saved logs")
	fs.BoolVar(&raw.logDirSplit, "log-dir-split", false, "Save one file per extracted log")
	fs.BoolVar(&raw.logDirAll, "log-dir-all", false, "Save logs for all scanned runs")
	fs.StringVar(&raw.manifestFile, "manifest-file", "", "Manifest file path")
	fs.StringVar(&raw.stateFile, "state-file", "", "State file path")

	normalizedArgs, err := normalizeArgs(args)
	if err != nil {
		return rawFlags{}, err
	}

	if err := fs.Parse(normalizedArgs); err != nil {
		return rawFlags{}, err
	}

	return raw, nil
}

func loadManifest(path string) (*config.Manifest, error) {
	if path == "" {
		return nil, nil
	}

	manifest, err := config.LoadManifest(path)
	if err == nil {
		return manifest, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	return nil, err
}

func buildConfig(raw rawFlags, manifest *config.Manifest, getenv func(string) string, now func() time.Time) (config.Config, error) {
	token := strings.TrimSpace(getenv("GITHUB_TOKEN"))
	if token == "" {
		return config.Config{}, fmt.Errorf("missing GitHub token: set GITHUB_TOKEN")
	}

	if raw.maxRuns < 0 {
		return config.Config{}, fmt.Errorf("invalid --max-runs: must be >= 0")
	}
	if raw.workers <= 0 {
		return config.Config{}, fmt.Errorf("invalid --workers: must be > 0")
	}
	if raw.stateFile != "" && raw.manifestFile == "" {
		return config.Config{}, fmt.Errorf("invalid --state-file: requires --manifest-file")
	}
	if raw.logDirSplit && raw.logDir == "" {
		return config.Config{}, fmt.Errorf("invalid --log-dir-split: requires --log-dir")
	}
	if raw.logDirAll && raw.logDir == "" {
		return config.Config{}, fmt.Errorf("invalid --log-dir-all: requires --log-dir")
	}

	format := config.OutputFormat(raw.format)
	if !format.Valid() {
		return config.Config{}, fmt.Errorf("invalid --format %q: must be json or csv", raw.format)
	}

	detectorName := raw.detectorName
	orgs := raw.orgs.Values()
	repos := raw.repos.Values()
	sinceInput := raw.since
	untilInput := raw.until

	if manifest != nil {
		detectorName = manifest.Detector
		orgs = append([]string(nil), manifest.Orgs...)
		repos = append([]string(nil), manifest.Repos...)
		sinceInput = manifest.RequestedSince.UTC().Format(time.RFC3339)
		untilInput = manifest.RequestedUntil.UTC().Format(time.RFC3339)
	}

	meta, ok := detector.Lookup(detectorName)
	if !ok {
		return config.Config{}, fmt.Errorf("invalid --detector %q: must be one of %s", detectorName, strings.Join(detector.Names(), ", "))
	}

	for _, repo := range repos {
		if !isOwnerRepo(repo) {
			return config.Config{}, fmt.Errorf("invalid --repo %q: must use owner/repo format", repo)
		}
	}

	if manifest == nil && len(orgs) == 0 && len(repos) == 0 {
		return config.Config{}, fmt.Errorf("missing scan targets: provide --org, --repo, or an existing --manifest-file")
	}
	if manifest != nil && len(repos) == 0 {
		return config.Config{}, fmt.Errorf("manifest resolution produced zero repos")
	}

	since, err := resolveTime(sinceInput, meta.DefaultSince)
	if err != nil {
		return config.Config{}, fmt.Errorf("invalid --since: %w", err)
	}

	defaultUntil := meta.DefaultUntil
	if meta.DefaultUntilNow {
		defaultUntil = now().UTC()
	}

	until, err := resolveTime(untilInput, defaultUntil)
	if err != nil {
		return config.Config{}, fmt.Errorf("invalid --until: %w", err)
	}

	return config.Config{
		Token:            token,
		OutputFile:       raw.output,
		Format:           format,
		Detector:         detectorName,
		Orgs:             orgs,
		Repos:            repos,
		Since:            since.UTC(),
		Until:            until.UTC(),
		MaxRuns:          raw.maxRuns,
		Workers:          raw.workers,
		Verbose:          raw.verbose,
		DryRun:           raw.dryRun,
		LogDir:           raw.logDir,
		LogDirSplit:      raw.logDirSplit,
		SaveAllLogs:      raw.logDirAll,
		ManifestFile:     raw.manifestFile,
		StateFile:        raw.stateFile,
		ExistingManifest: manifest,
	}, nil
}

func normalizeArgs(args []string) ([]string, error) {
	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		switch {
		case arg == "--token" || arg == "-t" || strings.HasPrefix(arg, "--token=") || strings.HasPrefix(arg, "-t="):
			return nil, fmt.Errorf("token flags are disabled: use GITHUB_TOKEN instead")
		case arg == "-r":
			normalized = append(normalized, "--repo")
		case strings.HasPrefix(arg, "-r="):
			normalized = append(normalized, "--repo="+strings.TrimPrefix(arg, "-r="))
		case arg == "-f":
			normalized = append(normalized, "--format")
		case strings.HasPrefix(arg, "-f="):
			normalized = append(normalized, "--format="+strings.TrimPrefix(arg, "-f="))
		case arg == "-w":
			normalized = append(normalized, "--workers")
		case strings.HasPrefix(arg, "-w="):
			normalized = append(normalized, "--workers="+strings.TrimPrefix(arg, "-w="))
		case arg == "-v":
			normalized = append(normalized, "--verbose")
		case strings.HasPrefix(arg, "-v="):
			normalized = append(normalized, "--verbose="+strings.TrimPrefix(arg, "-v="))
		default:
			normalized = append(normalized, arg)
		}
	}
	return normalized, nil
}

func resolveTime(raw string, fallback time.Time) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback.UTC(), nil
	}

	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}

	return parsed.UTC(), nil
}

func isOwnerRepo(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return false
	}

	return parts[0] != "" && parts[1] != ""
}
