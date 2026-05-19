package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderSkipsEmptySlots(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	progress := NewProgress(buf, 10, 2)
	progress.SetStatus("discovering workflow runs in navikt/example")
	progress.render()

	if strings.Contains(buf.String(), "run=0") {
		t.Fatalf("render unexpectedly showed empty worker slot:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "repos [------------------------] 0/10 | runs found 0") {
		t.Fatalf("render missing enumeration summary:\n%s", buf.String())
	}
}

func TestRenderSkipsUnchangedFrames(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	progress := NewProgress(buf, 10, 1)
	progress.SetStatus("enumerating repos")
	progress.render()
	first := buf.Len()
	progress.render()
	if buf.Len() != first {
		t.Fatalf("render wrote duplicate unchanged frame")
	}
}

func TestEnumerationLineIsCompacted(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	progress := NewProgress(buf, 3894, 1)
	progress.SetEnumerationDone(273)
	progress.SetKnownRuns(812)
	progress.SetStatus("discovering workflow runs in navikt/tpt-backend")
	progress.render()

	got := buf.String()
	if strings.Contains(got, "discovering workflow runs in navikt/tpt-backend") {
		t.Fatalf("enumeration line was not compacted:\n%s", got)
	}
	if !strings.Contains(got, "273/3894 | runs found 812") {
		t.Fatalf("enumeration progress missing:\n%s", got)
	}
}

func TestRenderShowsScanningPhaseSeparately(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	progress := NewProgress(buf, 10, 1)
	progress.SetStatus("discovering workflow runs in navikt/example")
	progress.SetEnumerationDone(2)
	progress.SetKnownRuns(25)
	progress.BeginScanning()
	progress.SetStatus("scanning workflows")
	progress.render()

	got := buf.String()
	if strings.Contains(got, "scanning workflows") {
		t.Fatalf("render should not duplicate phase label in progress line:\n%s", got)
	}
	if !strings.Contains(got, "runs [------------------------] 0/25 | findings 0") {
		t.Fatalf("render missing scanning progress:\n%s", got)
	}
}

func TestClearRemovesRenderedLine(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	progress := NewProgress(buf, 10, 1)
	progress.SetEnumerationDone(1)
	progress.render()
	if buf.Len() == 0 {
		t.Fatal("render wrote nothing")
	}

	progress.Clear()
	if !strings.Contains(buf.String(), "\x1b[2K") {
		t.Fatalf("clear did not emit terminal clear sequence: %q", buf.String())
	}
}

func TestFinishKeepsRenderedLineAndAddsNewline(t *testing.T) {
	t.Parallel()

	buf := new(bytes.Buffer)
	progress := NewProgress(buf, 10, 1)
	progress.SetEnumerationDone(1)
	progress.render()
	before := buf.String()

	progress.Finish()
	after := buf.String()
	if !strings.HasSuffix(after, "\n") {
		t.Fatalf("finish did not add newline: %q", after)
	}
	if strings.Contains(after[len(before):], "\x1b[2K") {
		t.Fatalf("finish unexpectedly cleared rendered line: %q", after)
	}
}
