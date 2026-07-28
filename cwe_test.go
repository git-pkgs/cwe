package cwe

import (
	"slices"
	"testing"
)

func TestLookup(t *testing.T) {
	id, e, ok := Lookup("79")
	if !ok || id != "CWE-79" || e.Name == "" {
		t.Fatalf("CWE-79: ok=%v id=%q name=%q", ok, id, e.Name)
	}
	if e.Category != "Injection" {
		t.Errorf("CWE-79 category: got %q want %q", e.Category, "Injection")
	}
	if _, e2, _ := Lookup("cwe-79"); e2.Name != e.Name {
		t.Error("case-insensitive lookup failed")
	}
	if id, _, _ := Lookup("  CWE-79  "); id != "CWE-79" {
		t.Errorf("whitespace not trimmed: %q", id)
	}
	if _, _, ok := Lookup("CWE-999999"); ok {
		t.Error("unknown id should miss")
	}
	if _, _, ok := Lookup(""); ok {
		t.Error("empty id should miss")
	}
}

func TestCategories(t *testing.T) {
	cats := Categories()
	if len(cats) != len(categoryID) {
		t.Fatalf("catalogue has %d View-1400 categories, categoryID map has %d",
			len(cats), len(categoryID))
	}
	if !slices.IsSorted(cats) {
		t.Error("categories should be sorted alphabetically")
	}
	for _, want := range []string{"Injection", "Memory Safety", "Access Control"} {
		if !slices.Contains(cats, want) {
			t.Errorf("missing category %q", want)
		}
	}
	// Every category label seen in the catalogue must have a hardcoded ID,
	// so a MITRE addition to View-1400 fails this test rather than silently
	// returning "" from CategoryID.
	for _, c := range cats {
		if CategoryID(c) == "" {
			t.Errorf("category %q has no hardcoded ID", c)
		}
	}
}

func TestInCategory(t *testing.T) {
	ids := InCategory("Injection")
	if len(ids) == 0 {
		t.Fatal("Injection should have members")
	}
	if !slices.IsSorted(ids) {
		t.Error("InCategory result should be sorted")
	}
	if !slices.Contains(ids, "CWE-79") {
		t.Errorf("Injection should include CWE-79, got %v", ids[:min(5, len(ids))])
	}
	if got := InCategory("Not A Real Category"); got != nil {
		t.Errorf("unknown category should return nil, got %v", got)
	}
}

func TestCategoryOf(t *testing.T) {
	if got := CategoryOf("CWE-79"); got != "CWE-1409" {
		t.Errorf("CategoryOf(CWE-79) = %q, want CWE-1409", got)
	}
	if got := CategoryOf("CWE-999999"); got != "" {
		t.Errorf("unknown id: got %q, want empty", got)
	}
}

func TestCategorizedIDs(t *testing.T) {
	ids := CategorizedIDs()
	if len(ids) == 0 {
		t.Fatal("CategorizedIDs should not be empty")
	}
	if !slices.IsSorted(ids) {
		t.Error("CategorizedIDs should be sorted")
	}
	total := 0
	for _, c := range Categories() {
		total += len(InCategory(c))
	}
	if total != len(ids) {
		t.Errorf("sum of per-category members = %d, CategorizedIDs = %d", total, len(ids))
	}
}
