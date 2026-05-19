package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/navikt/actologger/internal/cli"
	ghclient "github.com/navikt/actologger/internal/github"
	"github.com/navikt/actologger/internal/output"
	"github.com/navikt/actologger/internal/scanner"
)

func Run(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string, now func() time.Time) int {
	cfg, err := cli.Parse(args, stderr, getenv, now)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	level := slog.LevelInfo
	if cfg.Verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	graceful := make(chan struct{})
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	go func() {
		first := true
		for {
			select {
			case sig := <-signals:
				if first {
					logger.Info("graceful stop requested", "signal", sig.String())
					close(graceful)
					first = false
					continue
				}
				logger.Info("forcing cancellation", "signal", sig.String())
				cancel()
				return
			case <-runCtx.Done():
				return
			}
		}
	}()

	client := ghclient.New(cfg.Token, logger, graceful)

	result, err := scanner.Run(runCtx, scanner.Params{
		Config:       cfg,
		Logger:       logger,
		Stdout:       stdout,
		Stderr:       stderr,
		GitHub:       client,
		GracefulStop: graceful,
		Now:          now,
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return 130
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}

	if cfg.OutputFile == "" && !cfg.DryRun {
		data, err := output.FormatResult(cfg.Format, result)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := stdout.Write(data); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
	}

	return 0
}
