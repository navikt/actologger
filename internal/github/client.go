package github

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	go_github "github.com/google/go-github/v74/github"
	"golang.org/x/oauth2"

	"github.com/navikt/actologger/internal/detector"
)

var ErrGracefulStop = errors.New("graceful stop requested")

type RateLimitEvent struct {
	Remaining int
	ResetAt   time.Time
	Sleeping  bool
}

type AuthInfo struct {
	Username      string
	OAuthScopes   []string
	RateLimit     int
	RateRemaining int
	RateReset     time.Time
	UserForbidden bool
}

type WorkflowRun struct {
	ID        int64
	Name      string
	URL       string
	CreatedAt time.Time
}

type Client struct {
	api        *go_github.Client
	downloader *http.Client
	logger     *slog.Logger
	now        func() time.Time
	sleep      func(time.Duration)
	graceful   <-chan struct{}

	mu            sync.Mutex
	cooldownUntil time.Time

	OnRateLimit func(RateLimitEvent)
}

func New(token string, logger *slog.Logger, graceful <-chan struct{}) *Client {
	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	httpClient := oauth2.NewClient(context.Background(), src)

	return &Client{
		api:      go_github.NewClient(httpClient),
		logger:   logger,
		now:      time.Now,
		sleep:    time.Sleep,
		graceful: graceful,
		downloader: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				req.Header.Del("Authorization")
				return nil
			},
		},
	}
}

func (c *Client) ValidateToken(ctx context.Context, needsOrgScope bool) (AuthInfo, error) {
	if err := c.checkGraceful(ctx); err != nil {
		return AuthInfo{}, err
	}

	var info AuthInfo

	user, resp, err := c.api.Users.Get(ctx, "")
	if err != nil {
		var ghErr *go_github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusForbidden {
			info.UserForbidden = true
		} else {
			return AuthInfo{}, fmt.Errorf("get authenticated user: %w", err)
		}
	} else {
		info.Username = user.GetLogin()
		info.OAuthScopes = parseScopes(resp.Header.Get("X-OAuth-Scopes"))
	}

	rates, _, err := c.api.RateLimit.Get(ctx)
	if err != nil {
		return AuthInfo{}, fmt.Errorf("get rate limit: %w", err)
	}
	if rates != nil && rates.Core != nil {
		info.RateLimit = rates.Core.Limit
		info.RateRemaining = rates.Core.Remaining
		info.RateReset = rates.Core.Reset.Time.UTC()
	}

	if len(info.OAuthScopes) > 0 {
		if !hasAnyScope(info.OAuthScopes, "repo", "public_repo") {
			return AuthInfo{}, fmt.Errorf("token permission failure: missing repo or public_repo scope")
		}
		if needsOrgScope && !hasAnyScope(info.OAuthScopes, "read:org", "admin:org") {
			return AuthInfo{}, fmt.Errorf("token permission failure: missing read:org or admin:org scope")
		}
	}

	return info, nil
}

func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	var out []string
	opts := &go_github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: go_github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		if err := c.checkGraceful(ctx); err != nil {
			return nil, err
		}

		var repos []*go_github.Repository
		var resp *go_github.Response
		err := c.retry(ctx, func(ctx context.Context) error {
			var err error
			repos, resp, err = c.api.Repositories.ListByOrg(ctx, org, opts)
			if err == nil {
				c.recordCooldown(resp)
			}
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("list repos for org %s: %w", org, err)
		}

		for _, repo := range repos {
			if repo.GetArchived() {
				continue
			}
			out = append(out, repo.GetFullName())
		}
		if err := c.checkGraceful(ctx); err != nil {
			return nil, err
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return out, nil
}

func (c *Client) ListWorkflowRuns(ctx context.Context, owner, repo string, since, until time.Time) ([]WorkflowRun, error) {
	var out []WorkflowRun
	opts := &go_github.ListWorkflowRunsOptions{
		Created: fmt.Sprintf("%s..%s", since.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339)),
		ListOptions: go_github.ListOptions{
			PerPage: 100,
		},
	}

	for {
		if err := c.checkGraceful(ctx); err != nil {
			return nil, err
		}

		var runs *go_github.WorkflowRuns
		var resp *go_github.Response
		err := c.retry(ctx, func(ctx context.Context) error {
			var err error
			runs, resp, err = c.api.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
			if err == nil {
				c.recordCooldown(resp)
			}
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("list workflow runs for %s/%s: %w", owner, repo, err)
		}

		for _, run := range runs.WorkflowRuns {
			when := run.GetCreatedAt().Time
			if run.GetRunStartedAt().Time != (time.Time{}) {
				when = run.GetRunStartedAt().Time
			}
			name := run.GetDisplayTitle()
			if name == "" {
				name = run.GetName()
			}
			out = append(out, WorkflowRun{
				ID:        run.GetID(),
				Name:      name,
				URL:       run.GetHTMLURL(),
				CreatedAt: when.UTC(),
			})
		}
		if err := c.checkGraceful(ctx); err != nil {
			return nil, err
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return out, nil
}

func (c *Client) DownloadRunLogs(ctx context.Context, owner, repo string, runID int64) ([]detector.ExtractedLogFile, error) {
	if err := c.checkGraceful(ctx); err != nil {
		return nil, err
	}

	var downloadURL *url.URL
	err := c.retry(ctx, func(ctx context.Context) error {
		var resp *go_github.Response
		var err error
		downloadURL, resp, err = c.api.Actions.GetWorkflowRunLogs(ctx, owner, repo, runID, 0)
		if err == nil {
			c.recordCooldown(resp)
		}
		return err
	})
	if err != nil {
		var ghErr *go_github.ErrorResponse
		if errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("get workflow run log URL for %s/%s#%d: %w", owner, repo, runID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build log download request: %w", err)
	}
	req.Header.Del("Authorization")

	resp, err := c.downloader.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download workflow logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download workflow logs: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		return nil, fmt.Errorf("read workflow log archive: %w", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open workflow log archive: %w", err)
	}

	files := make([]detector.ExtractedLogFile, 0, len(reader.File))
	for _, file := range reader.File {
		if err := c.checkGraceful(ctx); err != nil {
			return nil, err
		}
		if !strings.HasSuffix(strings.ToLower(file.Name), ".txt") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open workflow log %s: %w", file.Name, err)
		}
		content, readErr := io.ReadAll(io.LimitReader(rc, 1<<20))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read workflow log %s: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close workflow log %s: %w", file.Name, closeErr)
		}
		files = append(files, detector.ExtractedLogFile{Name: file.Name, Content: string(content)})
	}

	return files, nil
}

func (c *Client) retry(ctx context.Context, fn func(context.Context) error) error {
	var attempt int
	for {
		if err := c.checkGraceful(ctx); err != nil {
			return err
		}

		if err := c.waitCooldown(ctx); err != nil {
			return err
		}

		err := fn(ctx)
		if err == nil {
			return nil
		}

		var rateErr *go_github.RateLimitError
		if errors.As(err, &rateErr) {
			wait := time.Until(rateErr.Rate.Reset.Time) + 10*time.Second
			if err := c.waitWithNotice(ctx, wait, rateErr.Rate.Remaining, rateErr.Rate.Reset.Time); err != nil {
				return err
			}
			continue
		}

		var abuseErr *go_github.AbuseRateLimitError
		if errors.As(err, &abuseErr) {
			wait := 60 * time.Second
			if abuseErr.GetRetryAfter() > 0 {
				wait = time.Duration(abuseErr.GetRetryAfter()) * time.Second
			}
			if err := c.waitWithNotice(ctx, wait, 0, c.now().UTC().Add(wait)); err != nil {
				return err
			}
			continue
		}

		if isTransient(err) && attempt < 3 {
			wait := time.Duration(1<<(attempt+1)) * time.Second
			attempt++
			if err := c.waitWithNotice(ctx, wait, 0, c.now().UTC().Add(wait)); err != nil {
				return err
			}
			continue
		}

		return err
	}
}

func (c *Client) checkGraceful(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	select {
	case <-c.graceful:
		return ErrGracefulStop
	default:
		return nil
	}
}

func (c *Client) recordCooldown(resp *go_github.Response) {
	if resp == nil || resp.Rate.Remaining >= 100 {
		return
	}
	reset := resp.Rate.Reset.Time.UTC().Add(10 * time.Second)
	c.mu.Lock()
	if reset.After(c.cooldownUntil) {
		c.cooldownUntil = reset
	}
	c.mu.Unlock()
}

func (c *Client) waitCooldown(ctx context.Context) error {
	c.mu.Lock()
	until := c.cooldownUntil
	c.mu.Unlock()

	if until.IsZero() || !until.After(c.now().UTC()) {
		return nil
	}
	return c.waitWithNotice(ctx, time.Until(until), 0, until)
}

func (c *Client) waitWithNotice(ctx context.Context, wait time.Duration, remaining int, reset time.Time) error {
	if wait <= 0 {
		return nil
	}
	if c.OnRateLimit != nil {
		c.OnRateLimit(RateLimitEvent{Remaining: remaining, ResetAt: reset.UTC(), Sleeping: true})
		defer c.OnRateLimit(RateLimitEvent{Remaining: remaining, ResetAt: reset.UTC(), Sleeping: false})
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	case <-c.graceful:
		return ErrGracefulStop
	}
}

func parseScopes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		scope := strings.TrimSpace(part)
		if scope != "" {
			out = append(out, scope)
		}
	}
	return out
}

func hasAnyScope(scopes []string, want ...string) bool {
	for _, have := range scopes {
		for _, candidate := range want {
			if have == candidate {
				return true
			}
		}
	}
	return false
}

func isTransient(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return true
	}

	var ghErr *go_github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		switch ghErr.Response.StatusCode {
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "unexpected eof") ||
		strings.Contains(msg, "eof")
}
