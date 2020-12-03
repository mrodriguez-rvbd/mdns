package mdns

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	// Log global instance of log for all packages
	log *zap.Logger
)

// Log gets the active logger, if no logger is found it will
// create a new instance of the logger
func Log() *zap.Logger {
	if log == nil {
		initLogger()
	}
	return log
}

// Get retrieve or create a new logger instance
func Get() *zap.Logger {
	if log == nil {
		initLogger()
	}
	return log
}

func initLogger() {
	var zapConfig zap.Config

	//logLevel := viper.GetString("level")
	logLevel := "warn"
	level := zap.NewAtomicLevelAt(zapcore.InfoLevel)
	switch logLevel {
	case "debug":
		level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	case "fatal":
		level = zap.NewAtomicLevelAt(zapcore.FatalLevel)
	case "panic":
		level = zap.NewAtomicLevelAt(zapcore.PanicLevel)
	}

	zapEncoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	if logLevel == "debug" {
		zapConfig = zap.Config{
			Level:         level,
			Development:   true,
			DisableCaller: false,
			Sampling: &zap.SamplingConfig{
				Initial:    100,
				Thereafter: 100,
			},
			Encoding:         "console",
			EncoderConfig:    zapEncoderConfig,
			OutputPaths:      []string{"stderr"},
			ErrorOutputPaths: []string{"stderr"},
		}
	} else {
		zapConfig = zap.Config{
			Level:         level,
			Development:   false,
			DisableCaller: true,
			Sampling: &zap.SamplingConfig{
				Initial:    100,
				Thereafter: 100,
			},
			Encoding:         "console",
			EncoderConfig:    zapEncoderConfig,
			OutputPaths:      []string{"stderr"},
			ErrorOutputPaths: []string{"stderr"},
		}
	}

	l, err := zapConfig.Build()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	log = l
}
