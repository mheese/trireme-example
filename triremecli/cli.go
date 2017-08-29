package triremecli

import (
	"fmt"
	"os"
	"os/signal"
	"strings"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-example/constructors"
	"github.com/aporeto-inc/trireme-example/extractors"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/cmd/remoteenforcer"
	"github.com/aporeto-inc/trireme/cmd/systemdutil"
	"github.com/aporeto-inc/trireme/enforcer"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/cliextractor"
	"github.com/aporeto-inc/trireme/monitor/dockermonitor"
	"github.com/aporeto-inc/trireme/processmon"
)

// KillContainerOnError defines if the Container is getting killed if the policy Application resulted in an error
const KillContainerOnError = true

// ProcessArgs handles all commands options for trireme
func ProcessArgs(arguments map[string]interface{}, processor enforcer.PacketProcessor) (err error) {

	if arguments["enforce"].(bool) {
		// Run enforcer and exit
		return remoteenforcer.LaunchRemoteEnforcer(processor)
	}

	if arguments["run"].(bool) || arguments["<cgroup>"] != nil {
		// Execute a command or process a cgroup cleanup and exit
		return processCmdArgs(arguments)
	}

	if !arguments["daemon"].(bool) {
		return fmt.Errorf("Invalid parameters")
	}

	// Trireme Daemon Commands
	processDaemonArgs(arguments, processor)
	return nil
}

func processCmdArgs(arguments map[string]interface{}) error {

	if arguments["run"].(bool) {

		var command string
		if value, ok := arguments["<command>"]; ok && value != nil {
			command = value.(string)
		}

		var labels []string
		if value, ok := arguments["--label"]; ok && value != nil {
			labels = value.([]string)
		}

		var serviceName string
		if value, ok := arguments["--service-name"]; ok && value != nil {
			serviceName = value.(string)
		}

		var ports string
		if value, ok := arguments["--ports"]; ok && value != nil {
			ports = value.(string)
		}

		portsSlice := []string{"0"}
		if len(ports) > 0 {
			portsSlice = strings.Split(ports, ",")
		}

		var params []string
		if value, ok := arguments["<params>"]; ok && value != nil {
			params = append(params, value.([]string)...)
		}

		return systemdutil.ExecuteCommandWithParameters(command, params, "", serviceName, portsSlice, labels)
	}

	var cgroup string
	if value, ok := arguments["<cgroup>"]; ok && value != nil {
		cgroup = value.(string)
	}

	return systemdutil.ExecuteCommandWithParameters("", nil, cgroup, "", nil, nil)

}

// processDaemonArgs is responsible for creating a trireme daemon
func processDaemonArgs(arguments map[string]interface{}, processor enforcer.PacketProcessor) {

	var t trireme.Trireme
	var m monitor.Monitor
	var rm monitor.Monitor
	var err error
	var customExtractor dockermonitor.DockerMetadataExtractor

	// Setup incoming args
	processmon.GlobalCommandArgs = arguments

	if arguments["--swarm"].(bool) {
		zap.L().Info("Using Docker Swarm extractor")
		customExtractor = extractors.SwarmExtractor
	} else if arguments["--extractor"].(bool) {
		extractorfile := arguments["<metadatafile>"].(string)
		zap.L().Info("Using custom extractor")
		customExtractor, err = cliextractor.NewExternalExtractor(extractorfile)
		if err != nil {
			zap.L().Fatal("External metadata extractor cannot be accessed", zap.Error(err))
		}
	}

	targetNetworks := []string{}
	if len(arguments["--target-networks"].([]string)) > 0 {
		zap.L().Info("Target Networks", zap.Strings("networks", arguments["--target-networks"].([]string)))
		targetNetworks = arguments["--target-networks"].([]string)
	}

	if !arguments["--hybrid"].(bool) {
		remote := arguments["--remote"].(bool)
		if arguments["--usePKI"].(bool) {
			keyFile := arguments["--keyFile"].(string)
			certFile := arguments["--certFile"].(string)
			caCertFile := arguments["--caCertFile"].(string)
			caCertKeyFile := arguments["--caKeyFile"].(string)
			zap.L().Info("Setting up trireme with PKI",
				zap.String("key", keyFile),
				zap.String("cert", certFile),
				zap.String("ca", caCertFile),
				zap.String("ca", caCertKeyFile),
			)
			t, m = constructors.TriremeWithCompactPKI(keyFile, certFile, caCertFile, caCertKeyFile, targetNetworks, &customExtractor, remote, KillContainerOnError)
		} else {
			zap.L().Info("Setting up trireme with PSK")
			t, m = constructors.TriremeWithPSK(targetNetworks, &customExtractor, remote, KillContainerOnError)
		}
	} else { // Hybrid mode
		if arguments["--usePKI"].(bool) {
			keyFile := arguments["--keyFile"].(string)
			certFile := arguments["--certFile"].(string)
			caCertFile := arguments["--caCertFile"].(string)
			caCertKeyFile := arguments["--caKeyFile"].(string)
			zap.L().Info("Setting up trireme with Compact PKI",
				zap.String("key", keyFile),
				zap.String("cert", certFile),
				zap.String("ca", caCertFile),
				zap.String("ca", caCertKeyFile),
			)
			t, m, rm = constructors.HybridTriremeWithCompactPKI(keyFile, certFile, caCertFile, caCertKeyFile, targetNetworks, &customExtractor, true, KillContainerOnError)
		} else {
			t, m, rm = constructors.HybridTriremeWithPSK(targetNetworks, &customExtractor, KillContainerOnError)
			if rm == nil {
				zap.L().Fatal("Failed to create remote monitor for hybrid")
			}
			zap.L().Info("Setting up trireme with PSK")
		}
	}

	if arguments["--cni"].(bool) {
		zap.L().Info("Setting up CNI trireme with PSK")
		t, m = constructors.TriremeCNIWithPSK(targetNetworks, false, KillContainerOnError)
	}

	if t == nil {
		zap.L().Fatal("Failed to create Trireme")
	}

	if m == nil {
		zap.L().Fatal("Failed to create Monitor")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Start services
	if err := t.Start(); err != nil {
		zap.L().Fatal("Failed to start Trireme")
	}

	if err := m.Start(); err != nil {
		zap.L().Fatal("Failed to start monitor")
	}

	if rm != nil {
		if err := rm.Start(); err != nil {
			zap.L().Fatal("Failed to start remote monitor")
		}
	}

	// Wait for Ctrl-C
	<-c

	fmt.Println("Bye!")
	m.Stop() // nolint
	t.Stop() // nolint
	if rm != nil {
		rm.Stop() // nolint
	}
}
