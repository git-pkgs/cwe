// Package cwe embeds the MITRE CWE catalogue and looks up entries by ID.
//
// Each entry carries the weakness name, its short description, and its
// View-1400 ("Comprehensive Categorization for Software Assurance Trends")
// category label. Deprecated weaknesses are excluded. The embedded catalogue
// is regenerated from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip via
// go generate.
package cwe

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
)

//go:generate go run ./gen -o cwe.json

//go:embed cwe.json
var catalogueJSON []byte

// Entry is one weakness in the catalogue. Category is the View-1400 bucket
// the weakness belongs to, or empty when the weakness is not mapped.
type Entry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category,omitempty"`
}

var (
	index          map[string]Entry
	categories     []string
	byCategory     map[string][]string
	categorizedIDs []string
)

// categoryID maps each View-1400 category label to its own CWE-ID. The
// mapping is stable (MITRE does not renumber View-1400) so it is hardcoded
// rather than derived from the catalogue at startup.
//
//nolint:goconst // a lookup table's keys are data, not repeated string literals
var categoryID = map[string]string{
	"Access Control":        "CWE-1396",
	"Comparison":            "CWE-1397",
	"Component Interaction": "CWE-1398",
	"Memory Safety":         "CWE-1399",
	"Concurrency":           "CWE-1401",
	"Encryption":            "CWE-1402",
	"Exposed Resource":      "CWE-1403",
	"File Handling":         "CWE-1404",
	"Improper Check or Handling of Exceptional Conditions": "CWE-1405",
	"Improper Input Validation":                            "CWE-1406",
	"Improper Neutralization":                              "CWE-1407",
	"Incorrect Calculation":                                "CWE-1408",
	"Injection":                                            "CWE-1409",
	"Insufficient Control Flow Management":                 "CWE-1410",
	"Insufficient Verification of Data Authenticity":       "CWE-1411",
	"Poor Coding Practices":                                "CWE-1412",
	"Protection Mechanism Failure":                         "CWE-1413",
	"Randomness":                                           "CWE-1414",
	"Resource Control":                                     "CWE-1415",
	"Resource Lifecycle Management":                        "CWE-1416",
	"Sensitive Information Exposure":                       "CWE-1417",
	"Violation of Secure Design Principles":                "CWE-1418",
}

func init() {
	if err := json.Unmarshal(catalogueJSON, &index); err != nil {
		panic("cwe: embedded catalogue: " + err.Error())
	}
	seen := map[string]bool{}
	byCategory = map[string][]string{}
	for id, e := range index {
		if e.Category == "" {
			continue
		}
		byCategory[e.Category] = append(byCategory[e.Category], id)
		categorizedIDs = append(categorizedIDs, id)
		if !seen[e.Category] {
			seen[e.Category] = true
			categories = append(categories, e.Category)
		}
	}
	sort.Strings(categories)
	sort.Strings(categorizedIDs)
	for _, ids := range byCategory {
		sort.Strings(ids)
	}
}

// Lookup accepts "CWE-79", "cwe-79", or "79" and returns the canonical ID and
// the entry. The bool is false when the ID is not in the catalogue.
func Lookup(raw string) (id string, e Entry, ok bool) {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	if raw == "" {
		return "", Entry{}, false
	}
	if !strings.HasPrefix(raw, "CWE-") {
		raw = "CWE-" + raw
	}
	e, ok = index[raw]
	return raw, e, ok
}

// Categories returns the View-1400 category labels in alphabetical order.
func Categories() []string { return categories }

// CategoryID returns the CWE-ID for a View-1400 category label, e.g.
// "Injection" -> "CWE-1409". Returns "" for an unknown label.
func CategoryID(label string) string { return categoryID[label] }

// CategoryOf returns the View-1400 category CWE-ID for a weakness ID, e.g.
// "CWE-352" -> "CWE-1411". Returns "" when the weakness is unknown or not
// mapped to a View-1400 bucket.
func CategoryOf(id string) string { return categoryID[index[id].Category] }

// InCategory returns the CWE-IDs that belong to a View-1400 category, sorted,
// or nil for an unknown category.
func InCategory(label string) []string { return byCategory[label] }

// CategorizedIDs returns every CWE-ID that has a View-1400 category, sorted.
func CategorizedIDs() []string { return categorizedIDs }
