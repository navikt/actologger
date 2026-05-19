package detector

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/navikt/actologger/internal/model"
)

const (
	NameMiniShaiHulud = "mini-shai-hulud"
	NameTrivy         = "trivy"
)

const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

type Definition struct {
	Name            string
	Description     string
	DefaultSince    time.Time
	DefaultUntil    time.Time
	DefaultUntilNow bool
	Patterns        []IndicatorPattern
	Suppressors     []MatchSuppressor
	FindingRule     FindingRule
}

type IndicatorPattern struct {
	Kind       string
	Name       string
	Value      string
	Display    string
	Confidence string
	Regex      *regexp.Regexp
}

func (p IndicatorPattern) Label() string {
	switch {
	case p.Display != "":
		return p.Display
	case p.Name != "":
		return p.Name + "@" + p.Value
	default:
		return p.Kind + ":" + p.Value
	}
}

type MatchSuppressor struct {
	Name  string
	Regex *regexp.Regexp
}

type FindingRule struct {
	AnyMatch            bool
	MinHighConfidence   int
	MinMediumConfidence int
	MinScore            int
}

func (r FindingRule) IsFinding(matches []model.Match) bool {
	if r.AnyMatch && len(matches) > 0 {
		return true
	}

	var high int
	var medium int
	var score int
	for _, match := range matches {
		switch match.Confidence {
		case ConfidenceHigh:
			high++
			score += 100
		case ConfidenceMedium:
			medium++
			score += 10
		case ConfidenceLow:
			score++
		}
	}

	if r.MinHighConfidence > 0 && high >= r.MinHighConfidence {
		return true
	}
	if r.MinMediumConfidence > 0 && medium >= r.MinMediumConfidence {
		return true
	}
	if r.MinScore > 0 && score >= r.MinScore {
		return true
	}

	return false
}

type ExtractedLogFile struct {
	Name    string
	Content string
}

type ScanResult struct {
	Matches           []model.Match
	SuppressedMatches []model.SuppressedMatch
	IsFinding         bool
	MatchSummary      string
	SuppressedSummary string
}

var registry = mustBuildRegistry()

func Lookup(name string) (Definition, bool) {
	definition, ok := registry[name]
	return definition, ok
}

func Names() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func Scan(def Definition, files []ExtractedLogFile) ScanResult {
	var matches []model.Match
	var suppressed []model.SuppressedMatch

	for fileIndex, file := range files {
		lines := strings.Split(file.Content, "\n")
		for lineIndex, line := range lines {
			suppressorName := matchedSuppressor(def.Suppressors, line)
			snippet := truncateSnippet(buildSnippet(lines, lineIndex))
			for _, pattern := range def.Patterns {
				if !pattern.Regex.MatchString(line) {
					continue
				}

				lineNumber := combinedLineNumber(files, fileIndex, lineIndex+1)
				if suppressorName != "" {
					suppressed = append(suppressed, model.SuppressedMatch{
						Pattern:  pattern.Label(),
						File:     file.Name,
						Line:     lineNumber,
						FileLine: lineIndex + 1,
						Reason:   suppressorName,
						Snippet:  snippet,
					})
					continue
				}

				matches = append(matches, model.Match{
					Pattern:    pattern.Label(),
					Kind:       pattern.Kind,
					Confidence: pattern.Confidence,
					File:       file.Name,
					Line:       lineNumber,
					FileLine:   lineIndex + 1,
					Snippet:    snippet,
				})
			}
		}
	}

	return ScanResult{
		Matches:           matches,
		SuppressedMatches: suppressed,
		IsFinding:         def.FindingRule.IsFinding(matches),
		MatchSummary:      MatchSummary(matches),
		SuppressedSummary: SuppressedSummary(suppressed),
	}
}

func MatchSummary(matches []model.Match) string {
	seen := make(map[string]struct{}, len(matches))
	labels := make([]string, 0, len(matches))
	for _, match := range matches {
		if _, ok := seen[match.Pattern]; ok {
			continue
		}
		seen[match.Pattern] = struct{}{}
		labels = append(labels, match.Pattern)
	}
	return strings.Join(labels, "; ")
}

func SuppressedSummary(matches []model.SuppressedMatch) string {
	seen := make(map[string]struct{}, len(matches))
	labels := make([]string, 0, len(matches))
	for _, match := range matches {
		label := fmt.Sprintf("%s (%s)", match.Pattern, match.Reason)
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		labels = append(labels, label)
	}
	return strings.Join(labels, "; ")
}

func matchedSuppressor(suppressors []MatchSuppressor, line string) string {
	for _, suppressor := range suppressors {
		if suppressor.Regex.MatchString(line) {
			return suppressor.Name
		}
	}
	return ""
}

func buildSnippet(lines []string, lineIndex int) string {
	parts := make([]string, 0, 3)
	if lineIndex > 0 {
		parts = append(parts, lines[lineIndex-1])
	}
	parts = append(parts, lines[lineIndex])
	if lineIndex+1 < len(lines) {
		parts = append(parts, lines[lineIndex+1])
	}
	return strings.Join(parts, "\n")
}

func truncateSnippet(snippet string) string {
	runes := []rune(snippet)
	if len(runes) <= 200 {
		return snippet
	}
	return string(runes[:200])
}

func combinedLineNumber(files []ExtractedLogFile, fileIndex int, fileLine int) int {
	line := 8 + fileLine
	for i := 0; i < fileIndex; i++ {
		line += countLines(files[i].Content) + 2
	}
	return line
}

func countLines(content string) int {
	return len(strings.Split(content, "\n"))
}

func compileLiteralPattern(kind, value, confidence string) IndicatorPattern {
	return IndicatorPattern{
		Kind:       kind,
		Value:      value,
		Confidence: confidence,
		Regex:      regexp.MustCompile(`(?i)` + regexp.QuoteMeta(value)),
	}
}

func compileNamedLiteralPattern(kind, name, value, confidence string) IndicatorPattern {
	pattern := compileLiteralPattern(kind, value, confidence)
	pattern.Name = name
	return pattern
}

func compileActionRefPattern(name, sha string) IndicatorPattern {
	quotedName := regexp.QuoteMeta(name)
	quotedSHA := regexp.QuoteMeta(sha)
	regex := `(?i)(?:` + quotedName + `@` + quotedSHA + `|` + quotedName + `.*\(SHA:` + quotedSHA + `\))`
	return IndicatorPattern{
		Kind:       "compromised-action-ref",
		Name:       name,
		Value:      sha,
		Confidence: ConfidenceHigh,
		Regex:      regexp.MustCompile(regex),
	}
}

func compileSuppressor(name, regex string) MatchSuppressor {
	return MatchSuppressor{
		Name:  name,
		Regex: regexp.MustCompile(regex),
	}
}

func mustBuildRegistry() map[string]Definition {
	return map[string]Definition{
		NameMiniShaiHulud: buildMiniShaiHulud(),
		NameTrivy:         buildTrivy(),
	}
}

func buildTrivy() Definition {
	patterns := make([]IndicatorPattern, 0, len(trivyActionRefs)+len(trivyNetworkIOCs)+len(trivyBinarySHA256)+len(trivyLateralMovementSHAs))
	for _, ref := range trivyActionRefs {
		patterns = append(patterns, compileActionRefPattern(ref.Name, ref.SHA))
	}
	for _, value := range trivyNetworkIOCs {
		patterns = append(patterns, compileLiteralPattern("network-ioc", value, ConfidenceHigh))
	}
	for _, value := range trivyBinarySHA256 {
		patterns = append(patterns, compileLiteralPattern("binary-sha256", value, ConfidenceHigh))
	}
	for _, value := range trivyLateralMovementSHAs {
		patterns = append(patterns, compileLiteralPattern("lateral-movement-sha", value, ConfidenceHigh))
	}

	return Definition{
		Name:         NameTrivy,
		Description:  "Detects Trivy compromise indicators in GitHub Actions logs.",
		DefaultSince: time.Date(2026, time.March, 19, 17, 0, 0, 0, time.UTC),
		DefaultUntil: time.Date(2026, time.March, 20, 6, 0, 0, 0, time.UTC),
		Patterns:     patterns,
		FindingRule:  FindingRule{AnyMatch: true},
	}
}

func buildMiniShaiHulud() Definition {
	patterns := make([]IndicatorPattern, 0, len(miniShaiHuludHighConfidence)+len(miniShaiHuludMediumConfidence))
	for _, indicator := range miniShaiHuludHighConfidence {
		patterns = append(patterns, compileLiteralPattern(indicator.Kind, indicator.Value, ConfidenceHigh))
	}
	for _, indicator := range miniShaiHuludMediumConfidence {
		patterns = append(patterns, compileLiteralPattern(indicator.Kind, indicator.Value, ConfidenceMedium))
	}

	suppressors := make([]MatchSuppressor, 0, len(miniShaiHuludSuppressors))
	for _, suppressor := range miniShaiHuludSuppressors {
		suppressors = append(suppressors, compileSuppressor(suppressor.Name, suppressor.Regex))
	}

	return Definition{
		Name:            NameMiniShaiHulud,
		Description:     "Detects Mini Shai-Hulud indicators in GitHub Actions logs.",
		DefaultSince:    time.Date(2026, time.May, 11, 0, 0, 0, 0, time.UTC),
		DefaultUntilNow: true,
		Patterns:        patterns,
		Suppressors:     suppressors,
		FindingRule: FindingRule{
			MinHighConfidence:   1,
			MinMediumConfidence: 2,
		},
	}
}
