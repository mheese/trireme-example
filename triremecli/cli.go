package triremecli

import (
	"fmt"
	"os"
	"os/signal"

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
	return systemdutil.ExecuteCommandFromArguments(arguments)
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

	policyFile := arguments["--policy"].(string)

	targetNetworks := []string{}
	if len(arguments["--target-networks"].([]string)) > 0 {
		zap.L().Info("Target Networks", zap.Strings("networks", arguments["--target-networks"].([]string)))
		targetNetworks = arguments["--target-networks"].([]string)
	}

	// Setup options
	cni := constructors.OptMonitor(
		constructors.SubOptMonitorCNI(),
	)
	if !arguments["--cni"].(bool) {
		cni = nil
	}

	remote := false
	hybrid := constructors.OptHybrid()
	if !arguments["--hybrid"].(bool) {
		remote = arguments["--remote"].(bool)
		hybrid = nil
	} else {
		zap.L().Info("Setting up trireme with Hybrid enforcement")
	}

	secretsOption := constructors.OptPSK([]byte("THIS IS A BAD PASSWORD"))
	if arguments["--usePKI"].(bool) {
		zap.L().Info("Setting up trireme with PKI")
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
		secretsOption = constructors.OptPKI(keyFile, certFile, caCertFile, caCertKeyFile)
	} else {
		zap.L().Info("Setting up trireme with PSK")
	}

	t := constructors.Trireme(
		hybrid,
		secretsOption,
		constructors.OptExtractor(customExtractor),
		constructors.OptPolicyFile(policyFile),
		constructors.OptFlags(remote, KillContainerOnError),
		constructors.OptTargetNetworks(targetNetworks),
	)

	if t == nil {
		zap.L().Fatal("Failed to create Trireme")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Start services
	if err := t.Start(); err != nil {
		zap.L().Fatal("Failed to start Trireme")
	}

	// Wait for Ctrl-C
	<-c

	fmt.Println("Bye!")

	t.Stop() // nolint
}
