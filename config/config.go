package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	trireme "github.com/aporeto-inc/trireme-lib"
	"github.com/spf13/viper"

	flag "github.com/spf13/pflag"
)

// TriremeEnvPrefix is the prefix used to provide configuration through env variables.
const TriremeEnvPrefix = "TRIREME"

// Configuration holds the whole configuration for Trireme-Example
type Configuration struct {
	// AuthType defines if Trireme uses PSK or PKI
	AuthType string
	// PSK is the PSK used for Trireme (if using PSK)
	PSK string
	// RemoteEnforcer defines if the enforcer is spawned into each POD namespace
	// or into the host default namespace.
	RemoteEnforcer bool

	DockerEnforcement bool
	// LinuxProcesses defines if we activate//police LinuxProcesses
	LinuxProcessesEnforcement bool

	// Set of Policies to be used with this example.
	PolicyFile string

	// Launch Trireme-Example with support for Swarm
	SwarmMode bool

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

	// Enforce defines if this process is an enforcer process (spawned into POD namespaces)
	Enforce bool `mapstructure:"Enforce"`
	// Run defines if this process is used to run a command
	Run bool
}

func usage() {
	flag.PrintDefaults()
	os.Exit(2)
}

// LoadConfig returns a config ready to use
func LoadConfig() (*Configuration, error) {
	flag.Usage = usage
	flag.String("AuthType", "", "Authentication type: PKI/PSK")
	flag.String("PSK", "", "PSK to use")
	flag.Bool("RemoteEnforcer", true, "Use the Trireme Remote Enforcer.")
	flag.Bool("LinuxProcesses", true, "LinuxProcesses defines if we activate//police LinuxProcesses.")
	flag.String("PolicyFile", "policy.json", "Set of Policies to be used with this example")
	flag.Bool("SwarmMode", false, "Launch Trireme-Example with support for Swarm")
	flag.String("CustomExtractor", "", "Launch Trireme-Example with support for CustomExtractor")
	flag.String("TriremeNetworks", "", "TriremeNetworks")
	flag.String("KeyPath", "", "KeyPath is the path to the Key in PEM encoded format")
	flag.String("CertPath", "", "CertPath is the path to the Cert in PEM encoded format")
	flag.String("CaCertPath", "", "CaCertPath is the path to the CaCert in PEM encoded format")
	flag.String("CaKeyPath", "", "CaKeyPath is the path to the CaKey in PEM encoded format")
	flag.String("LogLevel", "", "Log level. Default to info (trace//debug//info//warn//error//fatal)")
	flag.String("LogFormat", "", "Log Format. Default to human")
	flag.Bool("Enforce", false, "Run Trireme-Example in Enforce mode.")
	flag.Bool("Run", false, "Run Trireme-Example in Run mode.")

	// Setting up default configuration
	viper.SetDefault("AuthType", "PSK")
	viper.SetDefault("PSK", "PSK")
	viper.SetDefault("RemoteEnforcer", true)
	viper.SetDefault("LinuxProcesses", true)
	viper.SetDefault("PolicyFile", "policy.json")
	viper.SetDefault("SwarmMode", false)
	viper.SetDefault("CustomExtractor", "")
	viper.SetDefault("TriremeNetworks", "")
	viper.SetDefault("KeyPath", "")
	viper.SetDefault("CertPath", "")
	viper.SetDefault("CaCertPath", "")
	viper.SetDefault("CaKeyPath", "")
	viper.SetDefault("LogLevel", "info")
	viper.SetDefault("LogFormat", "human")
	viper.SetDefault("Enforce", false)
	viper.SetDefault("Run", false)

	// Binding ENV variables
	// Each config will be of format TRIREME_XYZ as env variable, where XYZ
	// is the upper case config.
	viper.SetEnvPrefix(TriremeEnvPrefix)
	viper.AutomaticEnv()

	// Binding CLI flags.
	flag.Parse()
	viper.BindPFlags(flag.CommandLine)

	var config Configuration

	// Manual check for Enforce mode as this is given as a simple argument
	if len(os.Args) > 1 {
		if os.Args[1] == "enforce" {
			config.Enforce = true
			config.LogLevel = viper.GetString("LogLevel")
			return &config, nil
		}
	}

	err := viper.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling:%s", err)
	}

	err = validateConfig(&config)
	if err != nil {
		return nil, err
	}

	// unset current Trireme Env variables as to keep a clean state for the remote enforcer process.
	unsetEnvVar(TriremeEnvPrefix)

	setupTriremeSubProcessArgs(&config)

	return &config, nil
}

// setupTriremeSubProcessArgs setups the logs for the remote Enforcer
func setupTriremeSubProcessArgs(config *Configuration) {
	logToConsole := true
	logWithID := false

	trireme.SetLogParameters(logToConsole, logWithID, config.LogLevel, config.LogFormat)
}

// validateConfig is validating the Configuration struct.
func validateConfig(config *Configuration) error {
	// Validating AUTHTYPE
	if config.AuthType != "PSK" && config.AuthType != "PKI" {
		return fmt.Errorf("AuthType should be PSK or PKI")
	}

	// Validating PSK
	if config.AuthType == "PSK" && config.PSK == "" {
		return fmt.Errorf("PSK should be provided")
	}

	parsedTriremeNetworks, err := parseTriremeNets(config.TriremeNetworks)
	if err != nil {
		return fmt.Errorf("TargetNetwork is invalid: %s", err)
	}
	config.ParsedTriremeNetworks = parsedTriremeNetworks

	return nil
}

// parseTriremeNets returns a parsed array of strings parsed based on white spaces between CIDR entries.
// An error is returned if any of the entries is not a valid IP CIDR.
func parseTriremeNets(nets string) ([]string, error) {
	resultNets := strings.Fields(nets)

	// Validation of each networks.
	for _, network := range resultNets {
		_, _, err := net.ParseCIDR(network)
		if err != nil {
			return nil, fmt.Errorf("Invalid CIDR: %s", err)
		}
	}
	return resultNets, nil
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
