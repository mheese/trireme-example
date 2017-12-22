package config

import (
	"fmt"
	"net"
	"os"
	"strings"

	docopt "github.com/docopt/docopt-go"
)

// GetArguments return the whole set of arguments for Trireme-Example
func GetArguments() (map[string]interface{}, error) {

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
    trireme-example enforce --log-id=<log-id>
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

	return docopt.Parse(usage, nil, true, "1.0.0rc2", false)

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
