package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/aporeto-inc/trireme-example/triremecli"
	docopt "github.com/docopt/docopt-go"
	"go.uber.org/zap"
)

// Configure configures the shared default logger.
func Configure(level string) zap.Config {

	config := zap.NewDevelopmentConfig()
	config.DisableStacktrace = true

	// Set the logger
	switch level {
	case "trace", "debug":
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	case "fatal":
		config.Level = zap.NewAtomicLevelAt(zap.FatalLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	zap.ReplaceGlobals(logger)

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

	return config
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
				[--influxdb]
        [--swarm|--extractor <metadatafile>]
        [--keyFile=<keyFile>]
        [--certFile=<certFile>]
        [--caCertFile=<caCertFile>]
	[--caKeyFile=<caKeyFile>]
        [--log-level=<log-level>]
    trireme-example enforce
        [--log-level=<log-level>]
    trireme-example <cgroup>

  Options:
    -h --help                              Show this help message and exit.
    --version                              show version and exit.
    --service-name=<sname>                 The name of the service to be launched.
    --label=<keyvalue>                     The metadata/labels associated with a service.
    --usePKI                               Use PKI for Trireme [default: false].
		--influxdb                             Use InluxDB to collect stats
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
  `

	arguments, _ := docopt.Parse(usage, nil, true, "1.0.0rc2", false)

	LogLevel := arguments["--log-level"].(string)

	Configure(LogLevel)

	triremecli.ProcessArgs(arguments, nil) //nolint
}
