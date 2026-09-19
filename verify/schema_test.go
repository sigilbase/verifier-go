package verify

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sigilbase/verifier-go/internal/difftest"
)

// result.schema.json describes the --json document. Without a JSON Schema
// validator in the standard library, this holds the shape to the schema
// the cheap way: every field a report writes is declared for its mode, and
// every field the schema requires is present. A validator run in CI or by
// hand (any draft 2020-12 implementation) is the full check.
func TestReportsFitTheSchemaShape(t *testing.T) {
	raw, err := os.ReadFile("../result.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			Verdict struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"verdictDocument"`
			Error struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"errorDocument"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("result.schema.json is not valid JSON: %v", err)
	}

	corpus, err := difftest.LoadCorpus("../corpus/expected.json")
	if err != nil {
		t.Fatal(err)
	}
	check := func(name string, rep *Report) {
		doc, err := rep.JSON()
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(doc, &parsed); err != nil {
			t.Fatal(err)
		}
		props, required := schema.Defs.Verdict.Properties, schema.Defs.Verdict.Required
		if rep.Hard {
			props, required = schema.Defs.Error.Properties, schema.Defs.Error.Required
		}
		for k := range parsed {
			if _, ok := props[k]; !ok {
				t.Errorf("%s: field %q is not in the schema", name, k)
			}
		}
		for _, k := range required {
			if _, ok := parsed[k]; !ok {
				t.Errorf("%s: required field %q missing", name, k)
			}
		}
		if !rep.Hard {
			switch rep.Mode {
			case "verify":
				mustHave(t, name, parsed, "bundle", "consistency_state")
			case "consistency-bundles":
				mustHave(t, name, parsed, "bundles", "consistency")
			case "consistency-recorded-root":
				mustHave(t, name, parsed, "bundle", "recorded")
			}
		}
	}

	for _, name := range corpus.SortedFixtures() {
		opts, path := optionsFromArgs(t, corpus.OptionsFor(name), "../corpus/"+name+".zip")
		opts.PrintHashes = true
		check(name, Bundle(path, opts))
	}
	for _, name := range corpus.SortedConsistency() {
		fx := corpus.Consistency[name]
		opts, _ := optionsFromArgs(t, corpus.ConsistencyOptionsFor(name), "")
		if fx.Old != "" {
			check(name, ConsistencyBundles("../corpus/"+fx.Old+".zip", "../corpus/"+fx.New+".zip", opts))
		}
		if fx.Bundle != "" {
			check(name, ConsistencyRecorded("../corpus/"+fx.Bundle+".zip", fx.Root, fx.Size, opts))
		}
	}
	check("missing path", Bundle("../corpus/does-not-exist.zip", Options{}))
}

func mustHave(t *testing.T, name string, doc map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := doc[k]; !ok {
			t.Errorf("%s: mode field %q missing", name, k)
		}
	}
}
