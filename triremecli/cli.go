package triremecli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-example/config"
	"github.com/aporeto-inc/trireme-example/constructors"
	"github.com/aporeto-inc/trireme-example/extractors"
	"github.com/aporeto-inc/trireme-example/policyexample"

	trireme "github.com/aporeto-inc/trireme-lib"
	"github.com/aporeto-inc/trireme-lib/cmd/systemdutil"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/monitor"
	"github.com/aporeto-inc/trireme-lib/monitor/dockermonitor"
)

// KillContainerOnError defines if the Container is getting killed if the policy Application resulted in an error
const KillContainerOnError = true

// ProcessArgs handles all commands options for trireme
func ProcessArgs(config config.Configuration) (err error) {

	if config.Enforce {
		return ProcessEnforce(config)
	}

	if config.Run || arguments["<cgroup>"] != nil {
		// Execute a command or process a cgroup cleanup and exit
		return processRun(config)
	}

	// Trireme Daemon Commands
	return processDaemon(config)
}

func processEnforce(config config.Configuration) (err error) {
	// Run enforcer and exit
	if err := trireme.LaunchRemoteEnforcer(processor); err != nil {
		zap.L().Fatal("Unable to start enforcer", zap.Error(err))
	}
	return nil
}

func processRun(config config.Configuration) (err error) {
	return systemdutil.ExecuteCommandFromArguments(arguments)
}

func processDaemon(config config.Configuration) (err error) {

	triremeOptions := []trireme.Option{}

	// Setting up Secret Auth type based on user config.
	var triremesecret secrets.Secrets
	if config.AuthType == "PSK" {
		zap.L().Info("Initializing Trireme with PSK Auth. Should NOT be used in production")

		triremesecret = secrets.NewPSKSecrets([]byte(config.PSK))

	} else if config.AuthType == "PKI" {
		zap.L().Info("Initializing Trireme with PKI Auth")

		triremesecret, err = utils.LoadCompactPKI(config.KeyPath, config.CertPath, config.CaCertPath, config.CaKeyPath)
		if err != nil {
			zap.L().Fatal("error creating PKI Secret for Trireme", zap.Error(err))
		}
	} else {
		zap.L().Fatal("No Authentication option given")
	}
	triremeOptions = append(triremeOptions, trireme.OptionSecret(triremesecret))

	// Setting up extractor and monitor
	monitorOptions := []trireme.MonitorOption{}

	if config.Docker {

		if config.Swarm {
			dockerOptions = append(dockerOptions, trireme.SubOptionMonitorDockerExtractor(extractors.SwarmExtractor))
		}

		monitorOptions = append(monitorOptions, trireme.OptionMonitorDocker(dockerOptions))
	}

	if config.LinuxProcesses {
		monitorOptions = append(monitorOptions, trireme.OptionMonitorLinuxProcess())
	}

	triremeOptions = append(triremeOptions, trireme.OptopmMonitors(monitorOptions))

	// Setting up PolicyResolver
	policyEngine := policyexample.NewCustomPolicyResolver(config.ParsedTriremeNetworks, config.policyFile)
	triremeOptions = append(triremeOptions, trireme.OptionPolicyResolver(policyEngine))

	t := trireme.New(triremeNodeName, triremeOptions...)
	if t == nil {
		zap.L().Fatal("Unable to initialize trireme")
	}

	// Start all the go routines.
	t.Start()
	zap.L().Debug("Trireme started")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	zap.L().Info("Everything started. Waiting for Stop signal")
	// Waiting for a Sig
	<-c

	zap.L().Debug("Stop signal received")
	t.Stop()
	zap.L().Debug("Trireme stopped")
	zap.L().Info("Everything stopped. Bye Trireme-Example!")

	return nil
}

// processDaemonArgs is responsible for creating a trireme daemon
func processDaemonArgs(config config.Configuration) {

	var t trireme.Trireme
	var m monitor.Monitor
	var rm monitor.Monitor
	var err error
	var customExtractor dockermonitor.DockerMetadataExtractor

	// Setup incoming args
	subProcessArgs := []string{}
	logToConsole := false
	logWithID := false
	if _, ok := arguments["--log-to-console"]; ok && arguments["--log-to-console"].(bool) {
		subProcessArgs = append(subProcessArgs, "--log-to-console")
		logToConsole = true
	} else {
		logWithID = true
		subProcessArgs = append(subProcessArgs, "--log-id")
	}
	trireme.SetupCommandArgs(logToConsole, logWithID, subProcessArgs)

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
			t, m = constructors.TriremeWithCompactPKI(keyFile, certFile, caCertFile, caCertKeyFile, targetNetworks, &customExtractor, remote, KillContainerOnError, policyFile)
		} else {
			zap.L().Info("Setting up trireme with PSK")
			t, m = constructors.TriremeWithPSK(targetNetworks, &customExtractor, remote, KillContainerOnError, policyFile)
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
			t, m, rm = constructors.HybridTriremeWithCompactPKI(keyFile, certFile, caCertFile, caCertKeyFile, targetNetworks, &customExtractor, true, KillContainerOnError, policyFile)
		} else {
			t, m, rm = constructors.HybridTriremeWithPSK(targetNetworks, &customExtractor, KillContainerOnError, policyFile)
			if rm == nil {
				zap.L().Fatal("Failed to create remote monitor for hybrid")
			}
			zap.L().Info("Setting up trireme with PSK")
		}
	}

	if arguments["--cni"].(bool) {
		zap.L().Info("Setting up CNI trireme with PSK")
		t, m = constructors.TriremeCNIWithPSK(targetNetworks, false, KillContainerOnError, policyFile)
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
