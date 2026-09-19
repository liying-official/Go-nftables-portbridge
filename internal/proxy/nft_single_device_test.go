package proxy

import "testing"

func TestNFTFlowtableDeviceJSONShapes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dev   any
		want  []string
		valid bool
	}{
		{"single-string", "a", []string{"a"}, true},
		{"single-array", []any{"a"}, []string{"a"}, true},
		{"multiple-array", []any{"b", "a"}, []string{"a", "b"}, true},
		{"wrong-single", "foreign", []string{"a"}, false},
		{"missing-second", "a", []string{"a", "b"}, false},
		{"empty-name", "", []string{"a"}, false},
		{"empty-list", []any{}, []string{"a"}, false},
		{"duplicate", []any{"a", "a"}, []string{"a", "b"}, false},
		{"null", nil, []string{"a"}, false},
		{"number", 1, []string{"a"}, false},
		{"object", map[string]any{"set": []any{"a"}}, []string{"a"}, false},
		{"mixed-list", []any{"a", 1}, []string{"a", "b"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := nftUnitSpec()
			objects := nftUnitObjects(spec)
			for _, object := range objects {
				if flow, ok := object["flowtable"].(map[string]any); ok {
					flow["dev"] = tc.dev
				}
			}
			err := validateNFTState(objects, []nftRuleSpec{spec}, tc.want, nftOwnerMarker(spec.ConntrackMark))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t: %v", tc.valid, err)
			}
		})
	}
}
