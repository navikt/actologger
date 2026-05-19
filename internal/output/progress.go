package output

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type WorkerPhase string

const (
	WorkerIdle        WorkerPhase = "idle"
	WorkerDownloading WorkerPhase = "downloading"
	WorkerMatching    WorkerPhase = "matching"
	WorkerDone        WorkerPhase = "done"
)

type WorkerSlot struct {
	Repo          string
	Workflow      string
	RunID         int64
	RunURL        string
	Phase         WorkerPhase
	FindingsCount int
}

type Progress struct {
	w          io.Writer
	mu         sync.Mutex
	known      int
	done       int
	totalRepos int
	enumDone   int
	findings   int
	rateMsg    string
	statusLine string
	scanning   bool
	slots      []WorkerSlot
	ticker     *time.Ticker
	stop       chan struct{}
	stopped    bool
	lines      int
	lastFrame  string
}

func NewProgress(w io.Writer, totalRepos, workers int) *Progress {
	return &Progress{
		w:          w,
		totalRepos: totalRepos,
		slots:      make([]WorkerSlot, workers),
		stop:       make(chan struct{}),
	}
}

func (p *Progress) Start() {
	p.ticker = time.NewTicker(100 * time.Millisecond)
	go func() {
		for {
			select {
			case <-p.ticker.C:
				p.render()
			case <-p.stop:
				return
			}
		}
	}()
}

func (p *Progress) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
	p.clearLocked()
}

func (p *Progress) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
}

func (p *Progress) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopLocked()
	if p.lines > 0 {
		fmt.Fprint(p.w, "\n")
	}
	p.lines = 0
	p.lastFrame = ""
}

func (p *Progress) SetKnownRuns(v int) { p.mu.Lock(); p.known = v; p.mu.Unlock() }
func (p *Progress) IncrementDone()     { p.mu.Lock(); p.done++; p.mu.Unlock() }
func (p *Progress) IncrementFindings() { p.mu.Lock(); p.findings++; p.mu.Unlock() }
func (p *Progress) SetEnumerationDone(v int) {
	p.mu.Lock()
	p.enumDone = v
	p.mu.Unlock()
}

func (p *Progress) SetStatus(line string) {
	p.mu.Lock()
	p.statusLine = line
	p.mu.Unlock()
}

func (p *Progress) BeginScanning() {
	p.mu.Lock()
	p.scanning = true
	p.mu.Unlock()
}

func (p *Progress) SetRateLimitMessage(msg string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rateMsg = msg
}

func (p *Progress) UpdateSlot(index int, slot WorkerSlot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if index >= 0 && index < len(p.slots) {
		p.slots[index] = slot
	}
}

func (p *Progress) Notice(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clearLocked()
	fmt.Fprintln(p.w, line)
	p.renderLocked()
}

func (p *Progress) render() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.renderLocked()
}

func (p *Progress) renderLocked() {
	var line string
	if !p.scanning {
		line = fmt.Sprintf("repos %s %d/%d | runs found %d",
			progressBar(p.enumDone, p.totalRepos, 24),
			p.enumDone,
			p.totalRepos,
			p.known,
		)
		if p.statusLine != "" {
			line += " | " + compactLabel(p.statusLine, 24)
		}
	} else {
		line = fmt.Sprintf("runs %s %d/%d | findings %d",
			progressBar(p.done, p.known, 24),
			p.done,
			p.known,
			p.findings,
		)
	}
	if p.rateMsg != "" {
		line += " | rl " + compactLabel(p.rateMsg, 28)
	}
	if line == "" {
		return
	}

	frame := line
	if frame == p.lastFrame {
		return
	}

	if p.lines > 0 {
		fmt.Fprint(p.w, "\r\x1b[2K")
	}
	fmt.Fprint(p.w, "\r")
	fmt.Fprint(p.w, frame)
	p.lines = 1
	p.lastFrame = frame
}

func (p *Progress) clearLocked() {
	if p.lines == 0 {
		return
	}
	fmt.Fprint(p.w, "\r\x1b[2K\r")
	p.lines = 0
	p.lastFrame = ""
}

func (p *Progress) stopLocked() {
	if p.stopped {
		return
	}
	close(p.stop)
	if p.ticker != nil {
		p.ticker.Stop()
	}
	p.stopped = true
}

func progressBar(done, total, width int) string {
	if width <= 0 {
		width = 10
	}
	if total <= 0 {
		return "[" + strings.Repeat("-", width) + "]"
	}

	filled := done * width / total
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}

	return "[" + strings.Repeat("#", filled) + strings.Repeat("-", width-filled) + "]"
}

func compactLabel(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}
