package main

import (
	"context"
	"os"
	"time"

	"github.com/navikt/actologger/internal/app"
)

func main() {
	os.Exit(app.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, os.Getenv, time.Now))
}
