package config_test

import (
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/jkoelker/ipv6relayd/pkg/config"
)

func TestDefaultConfigYAML(t *testing.T) {
	t.Parallel()

	expected := config.Default()

	data, err := yaml.Marshal(expected)
	if err != nil {
		t.Fatalf("marshal default config: %v", err)
	}

	var got config.Config
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal default config YAML: %v", err)
	}

	if !reflect.DeepEqual(expected, &got) {
		t.Fatalf("default config roundtrip mismatch:\nexpected: %+v\nactual: %+v\nYAML:\n%s", expected, &got, string(data))
	}
}
