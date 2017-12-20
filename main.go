package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aporeto-inc/trireme-example/triremecli"
	docopt "github.com/docopt/docopt-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// setLogs setups Zap to the correct log level and correct output format.
func setLogs(logFormat, logLevel string) error {
	var zapConfig zap.Config

	switch logFormat {
	case "json":
		zapConfig = zap.NewProductionConfig()
		zapConfig.DisableStacktrace = true
	default:
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.DisableStacktrace = true
		zapConfig.DisableCaller = true
		zapConfig.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {}
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Set the logger
	switch logLevel {
	case "trace":
		// TODO: Set the level correctly
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "debug":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	case "fatal":
		zapConfig.Level = zap.NewAtomicLevelAt(zap.FatalLevel)
	default:
		zapConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return err
	}

	go func(config zap.Config) {

		defaultLevel := config.Level
		var elevated bool

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGUSR1)
		for s := range c {
			if s == syscall.SIGINT {
				return
			}
			elevated = !elevated

			if elevated {
				config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
				zap.L().Info("Log level elevated to debug")
			} else {
				zap.L().Info("Log level restored to original configuration", zap.String("level", level))
				config.Level = defaultLevel
			}
		}
	}(config)

	zap.ReplaceGlobals(logger)

	return nil
}

func main() {

	usage := `Command for launching programs with Trireme policy.

  Usage:
    trireme-example -h | --help
    trireme-example --version
    trireme-example run
      [--service-name=<sname>]
      [[--label=<keyvalue>]...]
      [--ports=<ports>]
      <command> [--] [<params>...]
    trireme-example daemon
      [--target-networks=<networks>...]
      [--policy=<policyFile>]
      [--usePKI]
      [--hybrid|--remote|--local|--cni]
      [--swarm|--extractor <metadatafile>]
      [--keyFile=<keyFile>]
      [--certFile=<certFile>]
      [--caCertFile=<caCertFile>]
      [--caKeyFile=<caKeyFile>]
      [--log-level=<log-level>]
      [--log-level-remote=<log-level>]
      [--log-to-console]
    trireme-example enforce (--log-id=<log-id>|--log-to-console)
      [--log-level=<log-level>]
    trireme-example <cgroup>

  Options:
    -h --help                              Show this help message and exit.
    --version                              show version and exit.
    --service-name=<sname>                 The name of the service to be launched.
    --label=<keyvalue>                     The metadata/labels associated with a service.
    --usePKI                               Use PKI for Trireme [default: false].
    --certFile=<certFile>                  Certificate file [default: certs/cert.pem].
    --keyFile=<keyFile>                    Key file [default: certs/cert-key.pem].
    --caCertFile=<caCertFile>              CA certificate [default: certs/ca.pem].
    --caKeyFile=<caKeyFile>                CA key [default: certs/ca-key.pem].
    --hybrid                               Hybrid mode of deployment [default: false].
    --remote                               Remote mode of deployment [default: false].
    --cni                                  Remote mode of deployment [default: false].
    --local                                Local mode of deployment [default: true].
    --swarm                                Deploy Doccker Swarm metadata extractor [default: false].
    --extractor                            External metadata extractor [default: ].
    --policy=<policyFile>                  Policy file [default: policy.json].
    --target-networks=<networks>...        The target networks that Trireme should apply authentication [default: ]
    <cgroup>                               cgroup of process that are terminated.

Logging Options:
    --log-level=<log-level>                Log level [default: info].
    --log-level-remote=<log-level>         Log level for remote enforcers [default: info].
    --log-id=<log-id>                      Log identifier.
    --log-to-console                       Log to console [default: true].
  `

	arguments, _ := docopt.Parse(usage, nil, true, "1.0.0rc2", false)

	LogLevel := arguments["--log-level"].(string)

	if err := setLogs("human", LogLevel); err != nil {
		log.Fatalf("Error setting up logs: %s", err)
	}

	triremecli.ProcessArgs(arguments, nil) //nolint
}
