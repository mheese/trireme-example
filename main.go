package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aporeto-inc/trireme-example/configuration"
	"github.com/aporeto-inc/trireme-example/triremecli"
	"github.com/aporeto-inc/trireme-example/versions"
	trireme "github.com/aporeto-inc/trireme-lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func banner(version, revision string) {
	fmt.Printf(`


	  _____     _
	 |_   _| __(_)_ __ ___ _ __ ___   ___
	   | || '__| | '__/ _ \ '_'' _ \ / _ \
	   | || |  | | | |  __/ | | | | |  __/
	   |_||_|  |_|_|  \___|_| |_| |_|\___|


_______________________________________________________________
             %s - %s
                                                 🚀  by Aporeto

`, version, revision)
}

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
				zap.L().Info("Log level restored to original configuration", zap.String("level", logLevel))
				config.Level = defaultLevel
			}
		}
	}(zapConfig)

	zap.ReplaceGlobals(logger)

	return nil
}

func main() {
	cmdRun := &cobra.Command{
		Use:   "run [OPTIONS] <command> [--] [<params>...]",
		Short: "Run an application with a Trireme policy",
		Long:  "TODO",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("In RUN command", args)
			return
		},
	}
	cmdRun.Flags().String("service-name", "", "The name of the service to be launched")
	cmdRun.Flags().StringSlice("label", nil, "The metadata/labels associated with a service")
	cmdRun.Flags().StringSlice("ports", nil, "Ports that the executed service is listening to")
	cmdRun.Flags().Bool("networkonly", false, "Control traffic from the network only and not from applications")
	cmdRun.Flags().Bool("hostpolicy", false, "Default control of the base namespace")
	viper.BindPFlags(cmdRun.Flags())

	cmdRm := &cobra.Command{
		Use:   "rm [--service-id=<id> | --service-name=<sname>]",
		Short: "Remove Trireme policy from a running cgroup",
		Long:  "TODO",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("In RM command", args)
			return
		},
	}
	cmdRm.Flags().String("service-id", "", "The name of the service to be removed from Trireme")
	cmdRm.Flags().String("service-name", "", "The name of the service to be removed from Trireme")
	viper.BindPFlags(cmdRm.Flags())

	cmdDaemon := &cobra.Command{
		Use:   "daemon [ OPTIONS ]",
		Short: "Starts the Trireme daemon",
		Long:  "TODO",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("In DAEMON command", args)
			return
		},
	}
	cmdDaemon.Flags().StringSlice("target-networks", nil, "The target networks that Trireme should apply authentication")
	cmdDaemon.Flags().String("policy", "", "Policy file")
	cmdDaemon.Flags().Bool("usePKI", false, "Use PKI for Trireme")
	cmdDaemon.Flags().Bool("hybrid", false, "Hybrid mode of deployment (docker+processes)")
	cmdDaemon.Flags().Bool("local", false, "Local mode of deployment")
	cmdDaemon.Flags().Bool("remote", false, "Local mode of deployment")
	cmdDaemon.Flags().Bool("swarm", false, "Deploy Docker Swarm metadata extractor")
	cmdDaemon.Flags().String("extractor", "", "External metadata extractor")
	cmdDaemon.Flags().String("certFile", "", "Certificate file")
	cmdDaemon.Flags().String("keyFile", "", "Key file")
	cmdDaemon.Flags().String("caCertFile", "", "CA certificate")
	cmdDaemon.Flags().String("caKeyFile", "", "CA key")
	viper.BindPFlags(cmdDaemon.Flags())

	cmdEnforce := &cobra.Command{
		Use:   "enforce",
		Short: "Starts the Trireme remote enforcer daemon",
		Long:  "TODO",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("In ENFORCE command", args)
			return
		},
	}

	rootCmd := &cobra.Command{
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("In ROOT command", args)
			cmd.DebugFlags()
			viper.Debug()
			return
		},
		Short:   "trireme-example",
		Long:    "This is an example implementation of the trireme library",
		Version: versions.VERSION + " (" + versions.REVISION + ")",
	}
	rootCmd.SetVersionTemplate(`{{printf "%s " .Short}}{{printf "%s\n" .Version}}`)
	rootCmd.AddCommand(cmdRun, cmdRm, cmdDaemon, cmdEnforce)
	//rootCmd.PersistentFlags().Bool("version", false, "Show version and exit")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level")
	rootCmd.PersistentFlags().String("log-level-remote", "info", "Log level for remote enforcers")
	rootCmd.PersistentFlags().String("log-id", "", "Log identifier")
	rootCmd.PersistentFlags().Bool("log-to-console", true, "Log to console")
	viper.BindPFlags(rootCmd.PersistentFlags())
	err := rootCmd.Execute()
	if err != nil {
		log.Fatalf("Failed to run command: %s", err.Error())
	}
	os.Exit(0)

	config, err := configuration.LoadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %s", err)
	}

	if config.Enforce {
		_, _, config.LogLevel, config.LogFormat = trireme.GetLogParameters()
	}

	err = setLogs(config.LogFormat, config.LogLevel)
	if err != nil {
		log.Fatalf("Error setting up logs: %s", err)
	}

	if !config.Enforce && !config.Run {
		banner("14", "20")
		zap.L().Info("Current configuration", config.Fields()...)
		zap.L().Info("Current libraties versions", versions.Fields()...)
	}

	triremecli.ProcessArgs(config)
}
