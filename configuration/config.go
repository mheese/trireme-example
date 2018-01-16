package configuration

import (
	"fmt"
	"os"
	"strings"

	trireme "github.com/aporeto-inc/trireme-lib"
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

// ProductName is used in viper
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
const Usage = `Command for launching programs with Trireme policy.

  Usage:
    trireme-example -h | --help
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
    --hybrid                               Hybrid mode of deployment (docker+processes) [default: false].
    --local                                Local mode of deployment () [default: false].
    --swarm                                Deploy Doccker Swarm metadata extractor [default: false].
    --extractor                            External metadata extractor [default: ].
    --policy=<policyFile>                  Policy file [default: policy.json].
    --target-networks=<networks>...        The target networks that Trireme should apply authentication [default: ].
    --ports=<ports>                        Ports that the executed service is listening to [default ].
    --networkonly                          Control traffic from the network only and not from applications [default false].
    --hostpolicy                           Default control of the base namespace [default false].
    <cgroup>                               cgroup of process that are terminated.

Logging Options:
    --log-level=<log-level>                Log level [default: info].
    --log-level-remote=<log-level>         Log level for remote enforcers [default: info].
    --log-id=<log-id>                      Log identifier.
    --log-to-console                       Log to console [default: true].
  `

// LoadConfig returns a Configuration struct ready to use.
// TODO: It uses DocOpt as the end config manager. Eventually move everything in Viper.
func LoadConfig() (*Configuration, error) {
	var err error

	// define command line flags (we bind them later)
	//pflag.Usage = func() {
	//	fmt.Println(ProductName + " " + versions.VERSION + " (" + versions.REVISION + ")")
	//	fmt.Println()
	//	fmt.Println(Usage)
	//	os.Exit(2)
	//}
	//pflag.Bool("version", false, "Show version and exit")
	//pflag.String("service-name", "", "The name of the service to be launched")
	//pflag.StringSlice("label", nil, "The metadata/labels associated with a service")
	//pflag.Bool("usePKI", false, "Use PKI for Trireme")
	//pflag.String("certFile", "", "Certificate file")
	//pflag.String("keyFile", "", "Key file")
	//pflag.String("caCertFile", "", "CA certificate")
	//pflag.String("caKeyFile", "", "CA key")
	//pflag.Bool("hybrid", false, "Hybrid mode of deployment (docker+processes)")
	//pflag.Bool("local", false, "Local mode of deployment")
	//pflag.Bool("swarm", false, "Deploy Docker Swarm metadata extractor")
	//pflag.String("extractor", "", "External metadata extractor")
	//pflag.String("policy", "", "Policy file")
	//pflag.StringSlice("target-networks", nil, "The target networks that Trireme should apply authentication")
	//pflag.StringSlice("ports", nil, "Ports that the executed service is listening to")
	//pflag.Bool("networkonly", false, "Control traffic from the network only and not from applications")
	//pflag.Bool("hostpolicy", false, "Default control of the base namespace")
	//pflag.String("log-level", "info", "Log level")
	//pflag.String("log-level-remote", "info", "Log level for remote enforcers")
	//pflag.String("log-id", "", "Log identifier")
	//pflag.Bool("log-to-console", true, "Log to console")

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

	// 2. read config files
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/trireme-example/")
	viper.AddConfigPath("$HOME/.trireme-example/")
	viper.AddConfigPath(".")
	err = viper.ReadInConfig() // Find and read the config file
	if err != nil {
		// TODO: decide if we want to print an error
	}

	// 3. setup environment variables
	viper.SetEnvPrefix(TriremeEnvPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	//// 4. parse commandline flags
	//pflag.Parse()
	//viper.BindPFlags(pflag.CommandLine)

	// now read the configuration
	var config Configuration
	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize config: %s", err.Error())
	}

	// By default use a remote enforcer for Docker.
	//config.RemoteEnforcer = true

	//var oldArgs map[string]interface{}
	//oldArgs, err := getArguments()
	//if err != nil {
	//	return nil, err
	//}
	//config.Arguments = oldArgs

	//if oldArgs["run"].(bool) || oldArgs["rm"].(bool) || oldArgs["<cgroup>"] != nil {
	//	// Execute a command or process a cgroup cleanup and exit
	//	config.Run = true
	//}

	//if oldArgs["enforce"].(bool) {
	//	// Execute a command or process a cgroup cleanup and exit
	//	config.Enforce = true
	//}

	//if len(oldArgs["--target-networks"].([]string)) > 0 {
	//	config.ParsedTriremeNetworks = oldArgs["--target-networks"].([]string)
	//}

	//config.PolicyFile = oldArgs["--policy"].(string)

	//if oldArgs["--usePKI"].(bool) {
	//	config.Auth = PKI
	//	config.CertPath = oldArgs["--certFile"].(string)
	//	config.KeyPath = oldArgs["--keyFile"].(string)
	//	config.CaCertPath = oldArgs["--caCertFile"].(string)
	//	config.CaKeyPath = oldArgs["--caKeyFile"].(string)

	//} else {
	//	config.Auth = PSK
	//	config.PSK = "BADPASS"
	//}

	//config.DockerEnforcement = true
	//if oldArgs["--hybrid"].(bool) {
	//	config.LinuxProcessesEnforcement = true
	//}

	//if oldArgs["--local"].(bool) {
	//	config.RemoteEnforcer = false
	//}

	//if oldArgs["--swarm"].(bool) {
	//	config.SwarmMode = true
	//}

	//if oldArgs["--extractor"].(bool) {
	//	config.CustomExtractor = oldArgs["metadatafile"].(string)
	//}

	//config.LogLevel = oldArgs["--log-level"].(string)

	// unset current Trireme Env variables as to keep a clean state for the remote enforcer process.
	unsetEnvVar(TriremeEnvPrefix)

	setupTriremeSubProcessArgs(&config)

	return &config, nil
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
