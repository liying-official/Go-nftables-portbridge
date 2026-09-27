package proxy

import (
	"reflect"
	"testing"
)

var (
	_ nftBackend              = (*commandNFTBackend)(nil)
	_ nftHealthChecker        = (*commandNFTBackend)(nil)
	_ nftRetirementReporter   = (*commandNFTBackend)(nil)
	_ nftTelemetryReader      = (*commandNFTBackend)(nil)
	_ nftRulesetReader        = (*nftCommandIO)(nil)
	_ nftTelemetryTableReader = (*nftCommandIO)(nil)
)

func TestNFTOptionalCapabilityMethodSets(t *testing.T) {
	tests := []struct {
		name       string
		named, old reflect.Type
	}{
		{"health", reflect.TypeFor[nftHealthChecker](), reflect.TypeFor[interface {
			Healthy([]nftRuleSpec) (bool, error)
		}]()},
		{"retirement", reflect.TypeFor[nftRetirementReporter](), reflect.TypeFor[interface {
			retirementState() nftRetirementState
		}]()},
		{"telemetry", reflect.TypeFor[nftTelemetryReader](), reflect.TypeFor[interface {
			readTelemetry() (nftTelemetry, error)
		}]()},
		{"ruleset", reflect.TypeFor[nftRulesetReader](), reflect.TypeFor[interface {
			Ruleset() ([]byte, error)
		}]()},
		{"telemetry table", reflect.TypeFor[nftTelemetryTableReader](), reflect.TypeFor[interface {
			telemetryTable() ([]byte, error)
		}]()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.named.AssignableTo(test.old) || !test.old.AssignableTo(test.named) {
				t.Fatal("naming the optional interface changed its structural contract")
			}
		})
	}
}

// Deliberately implements only the required backend methods. Keep optional
// capabilities out of nftBackend so their absence still follows existing paths.
type minimalCapabilityBackend struct{}

func (minimalCapabilityBackend) Replace([]nftRuleSpec) error { return nil }
func (minimalCapabilityBackend) Delete() error               { return nil }
func (minimalCapabilityBackend) TopologyKey() string         { return "" }

func TestNFTOptionalCapabilityDetection(t *testing.T) {
	var backend nftBackend = minimalCapabilityBackend{}
	if _, ok := backend.(nftHealthChecker); ok {
		t.Fatal("minimal backend unexpectedly has a health capability")
	}
	if _, ok := backend.(nftRetirementReporter); ok {
		t.Fatal("minimal backend unexpectedly has a retirement capability")
	}
	if _, ok := backend.(nftTelemetryReader); ok {
		t.Fatal("minimal backend unexpectedly has a telemetry capability")
	}
}
