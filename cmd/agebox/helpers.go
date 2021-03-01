package main

import (
	"io"

	"github.com/sirupsen/logrus"
	"github.com/slok/agebox/internal/log"
	internallogrus "github.com/slok/agebox/internal/log/logrus"
)

// getLogger returns a logger.
func getLogger(config CmdConfig, stderr io.Writer) log.Logger {
	// Set up logger.
	var logger log.Logger = log.Noop
	logrusLog := logrus.New()
	logrusLog.Out = stderr // By default logger goes to stderr (so it can split stdout prints).
	logrusLogEntry := logrus.NewEntry(logrusLog)
	logger = internallogrus.NewLogrus(logrusLogEntry)
	logger.WithValues(log.Kv{"version": Version})
	return logger
}
