package configuration

import (
	"fmt"
	"os"
	"strings"

	"github.com/aporeto-inc/trireme-example/versions"
	trireme "github.com/aporeto-inc/trireme-lib"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// AuthType is a type that holds an Authentication method
type AuthType int

const (
	// PSK is the Authentication method that relies on a preshared Key (unsecure)
	PSK AuthType = iota + 1
	// PKI is the Authentication methid that relies on a PKI
	PKI
)

// ProductName is used in cobra/viper
const ProductName = "trireme-example"

// TriremeEnvPrefix is the prefix used to provide configuration through env variables.
const TriremeEnvPrefix = "TRIREME"

// Configuration holds the whole configuration for Trireme-Example
type Configuration struct {
	// Arguments is the retrocompatible format used to define the parameters//process to run
	Arguments map[string]interface{}
	// AuthType defines if Trireme uses PSK or PKI
	Auth AuthType
	// PSK is the PSK used for Trireme (if using PSK)
	PSK string

	// Set of Policies to be used with this example.
	PolicyFile string

	// Launch Trireme-Example with support for CustomExtractor
	CustomExtractor string

	// KeyPath is the path to the Key in PEM encoded format
	KeyPath string
	// CertPath is the path to the Cert in PEM encoded format
	CertPath string
	// CaCertPath is the path to the CaCert in PEM encoded format
	CaCertPath string
	// CaKeyPath is the path to the CaKey in PEM encoded format
	CaKeyPath string

	TriremeNetworks       string
	ParsedTriremeNetworks []string

	LogFormat string
	LogLevel  string

	// RemoteEnforcer defines if the enforcer is spawned into each POD namespace
	// or into the host default namespace.
	RemoteEnforcer bool

	DockerEnforcement bool
	// LinuxProcesses defines if we activate//police LinuxProcesses
	LinuxProcessesEnforcement bool

	// Launch Trireme-Example with support for Swarm
	SwarmMode bool

	// Enforce defines if this process is an enforcer process (spawned into POD namespaces)
	Enforce bool `mapstructure:"Enforce"`
	// Run defines if this process is used to run a command
	Run bool
}

// Usage is the whole help string for the executable
const Usage = `trireme-example -h | --help
  trireme-example --version

  trireme-example run
    [--service-name=<sname>]
    [[--label=<keyvalue>]...]
    [--ports=<ports>]
    [--networkonly]
    [--hostpolicy]
    <command> [--] [<params>...]

  trireme-example rm
    [--service-id=<id>]
    [--service-name=<sname>]

  trireme-example daemon
    [--target-networks=<networks>...]
    [--policy=<policyFile>]
    [--usePKI]
    [--hybrid|--remote|--local]
    [--swarm|--extractor <metadatafile>]
    [--keyFile=<keyFile>]
    [--certFile=<certFile>]
    [--caCertFile=<caCertFile>]
    [--caKeyFile=<caKeyFile>]
    [--log-level=<log-level>]
    [--log-level-remote=<log-level>]
    [--log-to-console]

  trireme-example enforce
    [--log-level=<log-level>]

  trireme-example <cgroup>
`

// InitCLI processes all commands and option flags, loads the configuration and
// prepares the CLI for execution. It returns the cobra instance which you should
// execute once ready to run the program. The arguments are the functions that
// should get executed once the CLI is started. `setLogs` is called to prepare zap.
// `banner` is called to print a CLI banner on daemon startup.
func InitCLI(runFunc, rmFunc, cgroupFunc, enforceFunc, daemonFunc func(*Configuration) error, setLogs func(logFormat, logLevel string) error, banner func()) *cobra.Command {
	var config Configuration
	config.Arguments = make(map[string]interface{})
	// if we don't initialize these as booleans, the systemdutil.ExecuteCommandFromArguments()
	// function will segfault
	config.Arguments["rm"] = false
	config.Arguments["run"] = false

	// initialize viper first
	// 1. initialize our default values
	viper.SetDefault("Auth", PSK)
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
	viper.SetConfigName("trireme-example")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.trireme-example/")
	viper.AddConfigPath("/etc/trireme-example/")
	viper.MergeInConfig()

	// 3. setup environment variables
	viper.SetEnvPrefix(TriremeEnvPrefix)
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
		Long:  "Run an application with a Trireme policy",
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
				// NOTE: cobra removes the first `--` already from args
				config.Arguments["<params>"] = args[1:]
			}

			// print configuration if in debug
			zap.L().Debug("prepared config", config.Fields()...)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// execute the actual command
			return runFunc(&config)
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
		Short: "Remove Trireme policy from a running service",
		Long:  "Remove Trireme policy from a running service",
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

			// print configuration if in debug
			zap.L().Debug("prepared config", config.Fields()...)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// execute the actual command
			return rmFunc(&config)
		},
	}
	fRmServiceID = cmdRm.Flags().String("service-id", "", "The name of the service to be removed from Trireme")
	fRmServiceName = cmdRm.Flags().String("service-name", "", "The name of the service to be removed from Trireme")

	// 3. daemon command
	var fUsePKI, fLocal *bool
	cmdDaemon := &cobra.Command{
		Use:   "daemon [ OPTIONS ]",
		Short: "Starts the Trireme daemon",
		Long:  "Starts the Trireme daemon",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			if fUsePKI != nil && *fUsePKI {
				config.Auth = PKI
			}
			if fLocal != nil && *fLocal {
				config.RemoteEnforcer = false
			}

			// print configuration if in debug
			zap.L().Debug("prepared config", config.Fields()...)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// display the banner for the daemon startup
			banner()
			zap.L().Info("Current configuration", config.Fields()...)
			zap.L().Info("Current library versions", versions.Fields()...)

			// execute the actual command
			return daemonFunc(&config)
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
		Long:  "Starts the Trireme remote enforcer daemon - you don't need to call this by yourself",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			config.Enforce = true

			// the remote enforcer needs to determine its logging parameters first
			_, _, config.LogLevel, config.LogFormat = trireme.GetLogParameters()

			// we then apply a different log level if this was requested
			if fLogLevelRemote != nil && len(*fLogLevelRemote) > 0 {
				config.LogLevel = *fLogLevelRemote
			}

			// redo the log setup
			err := setLogs(config.LogFormat, config.LogLevel)
			if err != nil {
				return fmt.Errorf("Error setting up logs: %s", err)
			}

			// print configuration if in debug
			zap.L().Debug("prepared config", config.Fields()...)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// execute the actual command
			return enforceFunc(&config)
		},
	}

	// 5. the root command: the main application entrypoint
	pfVersion := pflag.BoolP("version", "V", false, "Prints version information and exits")
	rootCmd := &cobra.Command{
		Use:  Usage,
		Long: "Command for launching programs with Trireme policy.",
		Args: cobra.MaximumNArgs(1),
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// check version information first and exit if it is requested
			if pfVersion != nil && *pfVersion {
				fmt.Printf("trireme-example %s (%s)\n", versions.VERSION, versions.REVISION)
				os.Exit(0)
			}
			// for all commands we want to apply our viper configuration first
			err := viper.Unmarshal(&config)
			if err != nil {
				return fmt.Errorf("failed to initialize config: %s", err.Error())
			}

			// setup logs
			err = setLogs(config.LogFormat, config.LogLevel)
			if err != nil {
				return fmt.Errorf("error setting up logs: %s", err)
			}
			return nil
		},
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("command takes exactly one argument: <cgroup>")
			}
			// the root command is also an own command: it takes the <cgroup> argument,
			// so it needs some more special commandline treatment here
			config.Run = true
			config.Arguments["<cgroup>"] = args[0]

			// print configuration if in debug
			zap.L().Debug("prepared config", config.Fields()...)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// execute the actual command
			return cgroupFunc(&config)
		},
	}
	rootCmd.AddCommand(cmdRun, cmdRm, cmdDaemon, cmdEnforce)
	rootCmd.PersistentFlags().AddFlag(pflag.Lookup("version"))
	rootCmd.PersistentFlags().String("log-level", "info", "Log level")
	rootCmd.PersistentFlags().String("log-format", "info", "Log Format")
	// TODO: not used at all?
	fLogLevelRemote = rootCmd.PersistentFlags().String("log-level-remote", "info", "Log level for remote enforcers")
	// TODO: not used at all?
	rootCmd.PersistentFlags().String("log-id", "", "Log identifier")
	// TODO: not used at all?
	rootCmd.PersistentFlags().Bool("log-to-console", true, "Log to console")
	viper.BindPFlag("LogLevel", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("LogFormat", rootCmd.PersistentFlags().Lookup("log-format"))

	// unset current Trireme Env variables as to keep a clean state for the remote enforcer process.
	unsetEnvVar(TriremeEnvPrefix)

	setupTriremeSubProcessArgs(&config)

	return rootCmd
}

// Fields returns a ready to dump zap.Fields containing all the configuration used.
func (c *Configuration) Fields() []zapcore.Field {
	fields := []zapcore.Field{
		zap.String("ParsedTriremeNetworks", c.TriremeNetworks),
		zap.Bool("RemoteEnforcer", c.RemoteEnforcer),
		zap.Bool("DockerEnforcement", c.DockerEnforcement),
		zap.Bool("LinuxProcessesEnforcement", c.LinuxProcessesEnforcement),
		zap.Bool("SwarmMode", c.SwarmMode),
	}

	if c.Auth == PSK {
		fields = append(fields, zap.String("AuthType", "PSK"))
	} else {
		fields = append(fields, zap.String("AuthType", "PKI"))
	}

	return fields
}

// setupTriremeSubProcessArgs setups the logs for the remote Enforcer
func setupTriremeSubProcessArgs(config *Configuration) {
	logToConsole := true
	logWithID := false

	trireme.SetLogParameters(logToConsole, logWithID, config.LogLevel, config.LogFormat)
}

// unsetEnvVar unsets all env variables with a specific prefix.
// Usage inside Trireme is to unset all Trireme env variables so
// that the remote doesn't get confused.
func unsetEnvVar(prefix string) {
	env := os.Environ()
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			kv := strings.Split(e, "=")
			if len(kv) > 0 {
				if err := os.Unsetenv(kv[0]); err != nil {
					continue
				}
			}
		}
	}
}
