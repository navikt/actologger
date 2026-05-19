package config

import "time"

type OutputFormat string

const (
	FormatJSON OutputFormat = "json"
	FormatCSV  OutputFormat = "csv"
)

func (f OutputFormat) Valid() bool {
	return f == FormatJSON || f == FormatCSV
}

type Config struct {
	Token            string
	OutputFile       string
	Format           OutputFormat
	Detector         string
	Orgs             []string
	Repos            []string
	Since            time.Time
	Until            time.Time
	MaxRuns          int
	Workers          int
	Verbose          bool
	DryRun           bool
	LogDir           string
	LogDirSplit      bool
	SaveAllLogs      bool
	ManifestFile     string
	StateFile        string
	ExistingManifest *Manifest
}
