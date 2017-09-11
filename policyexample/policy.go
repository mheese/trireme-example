package policyexample

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aporeto-inc/trireme"
	"github.com/aporeto-inc/trireme/monitor"
	"github.com/aporeto-inc/trireme/policy"
	"go.uber.org/zap"
)

// CustomPolicyResolver is a simple policy engine
type CustomPolicyResolver struct {
	triremeNets []string
	policies    map[string]*CachedPolicy
}

// CachedPolicy is a policy for a single container as read by a file
type CachedPolicy struct {
	ApplicationACLs *policy.IPRuleList
	NetworkACLs     *policy.IPRuleList
	TagSelectors    policy.TagSelectorList
}

// LoadPolicies loads a set of policies defined in a JSON file
func LoadPolicies(file string) map[string]*CachedPolicy {
	var config map[string]*CachedPolicy

	defaultConfig := &CachedPolicy{
		ApplicationACLs: &policy.IPRuleList{},
		NetworkACLs:     &policy.IPRuleList{},
		TagSelectors:    policy.TagSelectorList{},
	}

	configFile, err := os.Open(file)
	if err != nil {
		configFile.Close() //nolint
		zap.L().Warn("No policy file found - using defaults")
		return map[string]*CachedPolicy{
			"default": defaultConfig,
		}
	}

	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	if err != nil {
		zap.L().Error("Invalid policies - using default")
	}

	config["default"] = defaultConfig

	configFile.Close() //nolint

	return config
}

// GetPolicyIndex assumes that one of the labels of the PU is
// PolicyIndex and returns the corresponding value
func GetPolicyIndex(runtimeInfo policy.RuntimeReader) (string, error) {

	tags := runtimeInfo.Tags()

	for _, tag := range tags.GetSlice() {

		parts := strings.SplitN(tag, "=", 2)
		if strings.HasPrefix(parts[0], "@usr:PolicyIndex") {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("PolicyIndex Not Found")
}

// NewCustomPolicyResolver creates a new example policy engine for the Trireme package
func NewCustomPolicyResolver(networks []string, policyFile string) *CustomPolicyResolver {

	policies := LoadPolicies(policyFile)

	return &CustomPolicyResolver{
		triremeNets: networks,
		policies:    policies,
	}
}

// ResolvePolicy implements the Trireme interface. Here we just create a simple
// policy that accepts packets with the same labels as the target container.
// We also add some egress/ingress services
func (p *CustomPolicyResolver) ResolvePolicy(context string, runtimeInfo policy.RuntimeReader) (*policy.PUPolicy, error) {

	zap.L().Info("Getting Policy for ContainerID",
		zap.String("containerID", context),
		zap.String("name", runtimeInfo.Name()),
	)

	policyIndex, err := GetPolicyIndex(runtimeInfo)
	if err != nil {
		zap.L().Error("Cannot find requested policy index - Associating default policy - drop-all")
		policyIndex = "default"
	}

	puPolicy, ok := p.policies[policyIndex]
	if !ok {
		fmt.Println("I didn't find it in the cache ")
		return nil, fmt.Errorf("No policy found")
	}

	tagSelectors := puPolicy.TagSelectors
	// For the default policy we accept traffic with the same labels
	if policyIndex == "default" {
		tagSelectors = p.createDefaultRules(runtimeInfo)
	}

	// Use the bridge IP from Docker.
	ipl := policy.ExtendedMap{}
	if ip, ok := runtimeInfo.DefaultIPAddress(); ok {
		ipl[policy.DefaultNamespace] = ip
	}

	identity := runtimeInfo.Tags()

	annotations := runtimeInfo.Tags()

	excluded := []string{}

	containerPolicyInfo := policy.NewPUPolicy(context, policy.Police, *puPolicy.ApplicationACLs, *puPolicy.NetworkACLs, nil, tagSelectors, identity, annotations, ipl, p.triremeNets, excluded)

	return containerPolicyInfo, nil
}

// HandlePUEvent implements the corresponding interface. We have no
// state in this example
func (p *CustomPolicyResolver) HandlePUEvent(context string, eventType monitor.Event) {

	zap.L().Info("Handling container event",
		zap.String("containerID", context),
		zap.String("event", string(eventType)),
	)
}

// SetPolicyUpdater is used in order to register a pointer to the policyUpdater
// We don't implement policy updates in this example
func (p *CustomPolicyResolver) SetPolicyUpdater(pu trireme.PolicyUpdater) error {
	return nil
}

// CreateRuleDB creates a simple Rule DB that accepts packets from
// containers with the same labels as the instantiated container.
// If any of the labels matches, the packet is accepted.
func (p *CustomPolicyResolver) createDefaultRules(runtimeInfo policy.RuntimeReader) policy.TagSelectorList {

	selectorList := policy.TagSelectorList{}

	tags := runtimeInfo.Tags()

	for _, tag := range tags.GetSlice() {

		parts := strings.SplitN(tag, "=", 2)

		if !strings.HasPrefix(parts[0], "@usr") {
			continue
		}

		kv := policy.KeyValueOperator{
			Key:      parts[0],
			Value:    []string{parts[1]},
			Operator: policy.Equal,
		}

		tagSelector := policy.TagSelector{
			Clause: []policy.KeyValueOperator{kv},
			Policy: &policy.FlowPolicy{
				Action:   policy.Accept,
				PolicyID: "8",
			},
		}
		selectorList = append(selectorList, tagSelector)

	}

	// Add a default deny policy that rejects always from "namespace=bad"
	kv := policy.KeyValueOperator{
		Key:      "namespace",
		Value:    []string{"bad"},
		Operator: policy.Equal,
	}

	tagSelector := policy.TagSelector{
		Clause: []policy.KeyValueOperator{kv},
		Policy: &policy.FlowPolicy{
			Action:   policy.Reject,
			PolicyID: "9",
		},
	}

	selectorList = append(selectorList, tagSelector)

	for i, selector := range selectorList {
		for _, clause := range selector.Clause {
			zap.L().Info("Trireme policy for container",
				zap.String("name", runtimeInfo.Name()),
				zap.Int("c", i),
				zap.String("selector", fmt.Sprintf("%#v", clause)),
			)
		}
	}
	return selectorList

}
