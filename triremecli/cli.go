package triremecli

import (
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/aporeto-inc/trireme-example/configuration"
	"github.com/aporeto-inc/trireme-example/extractors"
	"github.com/aporeto-inc/trireme-example/policyexample"
	"github.com/aporeto-inc/trireme-example/utils"

	trireme "github.com/aporeto-inc/trireme-lib"
	"github.com/aporeto-inc/trireme-lib/cmd/systemdutil"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
)

// KillContainerOnError defines if the Container is getting killed if the policy Application resulted in an error
const KillContainerOnError = true

// ProcessArgs handles all commands options for trireme
func ProcessArgs(config *configuration.Configuration) (err error) {

	if config.Enforce {
		return ProcessEnforce(config)
	}

	if config.Run {
		// Execute a command or process a cgroup cleanup and exit
		return ProcessRun(config)
	}

	// Trireme Daemon Commands
	return ProcessDaemon(config)
}

// ProcessEnforce is called if the application is run as remote enforcer
func ProcessEnforce(config *configuration.Configuration) (err error) {
	// Run enforcer and exit

	if err := trireme.LaunchRemoteEnforcer(nil); err != nil {
		zap.L().Fatal("Unable to start enforcer", zap.Error(err))
	}
	return nil
}

// ProcessRun is called when the application is either adding or removing
// Trireme to a cgroup, or if an application is wrapped with trireme ("run")
func ProcessRun(config *configuration.Configuration) (err error) {
	return systemdutil.ExecuteCommandFromArguments(config.Arguments)
}

// ProcessDaemon is called when trireme-example is called to start the daemon
func ProcessDaemon(config *configuration.Configuration) (err error) {

	triremeOptions := []trireme.Option{}

	if config.LogLevel == "trace" {
		triremeOptions = append(triremeOptions, trireme.OptionPacketLogs())
	}

	// Setting up Secret Auth type based on user config.
	var triremesecret secrets.Secrets
	if config.Auth == configuration.PSK {
		zap.L().Info("Initializing Trireme with PSK Auth. Should NOT be used in production")

		triremesecret = secrets.NewPSKSecrets([]byte(config.PSK))

	} else if config.Auth == configuration.PKI {
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

	if config.DockerEnforcement {
		dockerOptions := []trireme.DockerMonitorOption{}

		if config.SwarmMode {
			dockerOptions = append(dockerOptions, trireme.SubOptionMonitorDockerExtractor(extractors.SwarmExtractor))
		}

		monitorOptions = append(monitorOptions, trireme.OptionMonitorDocker(dockerOptions...))
	}

	if config.LinuxProcessesEnforcement {
		monitorOptions = append(monitorOptions, trireme.OptionMonitorLinuxProcess())
		monitorOptions = append(monitorOptions, trireme.OptionMonitorLinuxHost())
		triremeOptions = append(triremeOptions, trireme.OptionEnforceLinuxProcess())
	}

	triremeOptions = append(triremeOptions, trireme.OptionMonitors(
		trireme.NewMonitor(monitorOptions...)),
	)

	// Setting up PolicyResolver
	policyEngine := policyexample.NewCustomPolicyResolver(config.ParsedTriremeNetworks, config.PolicyFile)
	triremeOptions = append(triremeOptions, trireme.OptionPolicyResolver(policyEngine))
	triremeOptions = append(triremeOptions, trireme.OptionDisableMutualAuth())

	triremeNodeName := "ExampleNodeName"
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
