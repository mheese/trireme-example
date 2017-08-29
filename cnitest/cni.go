package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/aporeto-inc/trireme/collector"
	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/monitor/cnimonitor"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
	"go.uber.org/zap"
)

type fakepuHandler struct{}

func (f *fakepuHandler) HandlePUEvent(a string, b monitor.Event) error {
	fmt.Printf("HANDLE-PU %s %+v \n", a, b)
	return nil
}

func (f *fakepuHandler) SetPURuntime(contextID string, runtimeInfo *policy.PURuntime) error {
	fmt.Printf("SET-PU %s %+v \n", contextID, runtimeInfo)
	return nil
}

func main() {
	fmt.Println("CNI Testing start")

	eventCollector := &collector.DefaultCollector{}
	puHandler := &fakepuHandler{}

	rpcmon, err := rpcmonitor.NewRPCMonitor(
		rpcmonitor.DefaultRPCAddress,
		puHandler,
		eventCollector,
	)
	if err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	// configure a LinuxServices processor for the rpc monitor
	cniProcessor := cnimonitor.NewCniProcessor(eventCollector, puHandler, cnimonitor.DockerCNIMetadataExtractor)
	if err := rpcmon.RegisterProcessor(constants.ContainerPU, cniProcessor); err != nil {
		zap.L().Fatal("Failed to initialize RPC monitor", zap.Error(err))
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// Start services
	if err := rpcmon.Start(); err != nil {
		zap.L().Fatal("Failed to start Trireme")
	}

	fmt.Println("CNI waiting")
	// Wait for Ctrl-C
	<-c

	fmt.Println("Bye!")
	rpcmon.Stop() // nolint

	fmt.Println("CNI Testing stop")

}
