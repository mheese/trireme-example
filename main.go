package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
	var err error
	var config configuration.Configuration
	config.Arguments = make(map[string]interface{})
	config.Arguments["rm"] = false
	config.Arguments["run"] = false

	// initialize viper first
	// 1. initialize our default values
	viper.SetDefault("Auth", configuration.PSK)
	viper.SetDefault("PSK", "BADPASS")
	viper.SetDefault("PolicyFile", "")
	viper.SetDefault("CustomExtractor", "")
	viper.SetDefault("KeyPath", "")
	viper.SetDefault("CertPath", "")
	viper.SetDefault("CaCertPath", "")
	viper.SetDefault("CaKeyPath", "")
	viper.SetDefault("TriremeNetworks", "")
	viper.SetDefault("ParsedTriremeNetworks", []string{})
	viper.SetDefault("LogFormat", "json")
	viper.SetDefault("LogLevel", "info")
	viper.SetDefault("RemoteEnforcer", true)
	viper.SetDefault("DockerEnforcement", true)
	viper.SetDefault("LinuxProcessesEnforcement", false)
	viper.SetDefault("SwarmMode", false)
	viper.SetDefault("Enforce", false)
	viper.SetDefault("Run", false)

	// 2. read config file: first one will be taken into account
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.trireme-example/")
	viper.AddConfigPath("/etc/trireme-example/")
	err = viper.ReadInConfig() // Find and read the config file
	if err != nil {
		zap.L().Debug("failed to read config file(s)", zapcore.Field{
			Key:    "error",
			Type:   zapcore.StringType,
			String: err.Error(),
		})
	}

	// 3. setup environment variables
	viper.SetEnvPrefix(configuration.TriremeEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// TODO: we probably need to declar them all manually to match all the
	//       the variables from docopts
	viper.AutomaticEnv()

	// now define all commands
	// 1. run command
	var fServiceName *string
	var fLabel, fPorts *[]string
	var fNetworkonly, fHostpolicy *bool
	cmdRun := &cobra.Command{
		Use:   "run [OPTIONS] <command> [--] [<params>...]",
		Short: "Run an application with a Trireme policy",
		Long:  "TODO",
		Args:  cobra.MinimumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			// manage setting of the rest of the configuration manually as we cannot
			// bind this with viper unfortunately
			config.Run = true
			config.Arguments["run"] = true
			if fServiceName != nil {
				config.Arguments["--service-name"] = *fServiceName
			}
			if fLabel != nil {
				config.Arguments["--label"] = *fLabel
			}
			if fPorts != nil {
				config.Arguments["--ports"] = *fPorts
			}
			if fNetworkonly != nil {
				config.Arguments["--networkonly"] = *fNetworkonly
			}
			if fHostpolicy != nil {
				config.Arguments["--hostpolicy"] = *fHostpolicy
			}

			// this works because we enforce a minimum of arguments to the command
			config.Arguments["<command>"] = args[0]

			if len(args) > 1 {
				// NOTE: this is taken care of by cobra: it removes the first `--`
				//if args[1] != "--" {
				//	return fmt.Errorf("invalid <command>")
				//}
				config.Arguments["<params>"] = args[1:]
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			// TODO: implement
		},
	}
	fServiceName = cmdRun.Flags().String("service-name", "", "The name of the service to be launched")
	fLabel = cmdRun.Flags().StringSlice("label", nil, "The metadata/labels associated with a service")
	fPorts = cmdRun.Flags().StringSlice("ports", nil, "Ports that the executed service is listening to")
	fNetworkonly = cmdRun.Flags().Bool("networkonly", false, "Control traffic from the network only and not from applications")
	fHostpolicy = cmdRun.Flags().Bool("hostpolicy", false, "Default control of the base namespace")

	// 2. rm command
	var fRmServiceID, fRmServiceName *string
	cmdRm := &cobra.Command{
		Use:   "rm [--service-id=<id> | --service-name=<sname>]",
		Short: "Remove Trireme policy from a running cgroup",
		Long:  "TODO",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			config.Run = true
			config.Arguments["rm"] = true
			if fRmServiceID != nil {
				config.Arguments["--service-id"] = *fRmServiceID
			}
			if fRmServiceName != nil {
				config.Arguments["--service-name"] = *fRmServiceName
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			//TODO: implement
		},
	}
	fRmServiceID = cmdRm.Flags().String("service-id", "", "The name of the service to be removed from Trireme")
	fRmServiceName = cmdRm.Flags().String("service-name", "", "The name of the service to be removed from Trireme")

	// 3. daemon command
	var fUsePKI, fLocal *bool
	cmdDaemon := &cobra.Command{
		Use:   "daemon [ OPTIONS ]",
		Short: "Starts the Trireme daemon",
		Long:  "TODO",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			if fUsePKI != nil && *fUsePKI {
				config.Auth = configuration.PKI
			}
			if fLocal != nil && *fLocal {
				config.RemoteEnforcer = false
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			// display the banner for the daemon startup
			banner("14", "20")
			zap.L().Info("Current configuration", config.Fields()...)
			zap.L().Info("Current library versions", versions.Fields()...)
		},
	}
	cmdDaemon.Flags().StringSlice("target-networks", nil, "The target networks that Trireme should apply authentication")
	cmdDaemon.Flags().String("policy", "", "Policy file")
	fUsePKI = cmdDaemon.Flags().Bool("usePKI", false, "Use PKI for Trireme")
	cmdDaemon.Flags().Bool("hybrid", false, "Hybrid mode of deployment (docker+processes)")
	fLocal = cmdDaemon.Flags().Bool("local", false, "Local mode of deployment")
	// TODO: looks superfluous
	cmdDaemon.Flags().Bool("remote", false, "Remote mode of deployment")
	cmdDaemon.Flags().Bool("swarm", false, "Deploy Docker Swarm metadata extractor")
	cmdDaemon.Flags().String("extractor", "", "External metadata extractor")
	cmdDaemon.Flags().String("certFile", "", "Certificate file")
	cmdDaemon.Flags().String("keyFile", "", "Key file")
	cmdDaemon.Flags().String("caCertFile", "", "CA certificate")
	cmdDaemon.Flags().String("caKeyFile", "", "CA key")
	viper.BindPFlag("ParsedTriremeNetworks", cmdDaemon.Flags().Lookup("target-networks"))
	viper.BindPFlag("PolicyFile", cmdDaemon.Flags().Lookup("policy"))
	viper.BindPFlag("CertPath", cmdDaemon.Flags().Lookup("certFile"))
	viper.BindPFlag("KeyPath", cmdDaemon.Flags().Lookup("keyFile"))
	viper.BindPFlag("CaCertPath", cmdDaemon.Flags().Lookup("caCertFile"))
	viper.BindPFlag("CaKeyPath", cmdDaemon.Flags().Lookup("caKeyFile"))
	viper.BindPFlag("LinuxProcessesEnforcement", cmdDaemon.Flags().Lookup("hybrid"))
	viper.BindPFlag("SwarmMode", cmdDaemon.Flags().Lookup("swarm"))
	viper.BindPFlag("CustomExtractor", cmdDaemon.Flags().Lookup("extractor"))

	// 4. enforce command
	var fLogLevelRemote *string
	cmdEnforce := &cobra.Command{
		Use:   "enforce",
		Short: "Starts the Trireme remote enforcer daemon",
		Long:  "TODO",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			config.Enforce = true

			// the remote enforcer needs to determine its logging parameters first
			_, _, config.LogLevel, config.LogFormat = trireme.GetLogParameters()

			// we then apply a different log level if this was requested
			if fLogLevelRemote != nil && len(*fLogLevelRemote) > 0 {
				config.LogLevel = *fLogLevelRemote
			}

			// redo the log setup
			// TODO: is there a better method than doing it twice?
			err = setLogs(config.LogFormat, config.LogLevel)
			if err != nil {
				log.Fatalf("Error setting up logs: %s", err)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			//TODO: implement
		},
	}

	// 5. the root command: the main application entrypoint
	rootCmd := &cobra.Command{
		Short:   "trireme-example",
		Long:    "This is an example implementation of the trireme library",
		Version: versions.VERSION + " (" + versions.REVISION + ")",
		Args:    cobra.ExactArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// for all commands we want to apply our viper configuration first
			err = viper.Unmarshal(&config)
			if err != nil {
				log.Fatalf("failed to initialize config: %s", err.Error())
			}

			// setup logs
			err = setLogs(config.LogFormat, config.LogLevel)
			if err != nil {
				log.Fatalf("Error setting up logs: %s", err)
			}
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			// the root command is also an own command: it takes the <cgroup> argument,
			// so it needs some more special commandline treatment here
			config.Run = true
			config.Arguments["<cgroup>"] = args[0]
		},
		Run: func(cmd *cobra.Command, args []string) {
			// TODO: implement
		},
	}
	rootCmd.SetVersionTemplate(`{{printf "%s " .Short}}{{printf "%s\n" .Version}}`)
	rootCmd.AddCommand(cmdRun, cmdRm, cmdDaemon, cmdEnforce)
	rootCmd.PersistentFlags().String("log-level", "info", "Log level")
	rootCmd.PersistentFlags().String("log-format", "info", "Log Format")
	// TODO: not used at all?
	fLogLevelRemote = rootCmd.PersistentFlags().String("log-level-remote", "info", "Log level for remote enforcers")
	// TODO: not used at all?
	rootCmd.PersistentFlags().String("log-id", "", "Log identifier")
	// TODO: not used at all?
	rootCmd.PersistentFlags().Bool("log-to-console", true, "Log to console")
	viper.BindPFlag("LogLevel", rootCmd.PersistentFlags().Lookup("log-level"))
	// TODO: LogFormat not used at all?
	viper.BindPFlag("LogFormat", rootCmd.PersistentFlags().Lookup("log-format"))

	// now run the defined cobra application
	err = rootCmd.Execute()
	if err != nil {
		log.Fatalf("Failed to run command: %s", err.Error())
	}
	//fmt.Printf("%#v\n", config)
	//os.Exit(0)

	//config, err := configuration.LoadConfig()
	//if err != nil {
	//	log.Fatalf("Error loading config: %s", err)
	//}

	//if config.Enforce {
	//	_, _, config.LogLevel, config.LogFormat = trireme.GetLogParameters()
	//}
	//if fLogLevelRemote != nil && len(*fLogLevelRemote) > 0 {
	//	config.LogLevel = *fLogLevelRemote
	//}

	//err = setLogs(config.LogFormat, config.LogLevel)
	//if err != nil {
	//	log.Fatalf("Error setting up logs: %s", err)
	//}

	//if !config.Enforce && !config.Run {
	//	banner("14", "20")
	//	zap.L().Info("Current configuration", config.Fields()...)
	//	zap.L().Info("Current libraties versions", versions.Fields()...)
	//}

	triremecli.ProcessArgs(&config)
}
