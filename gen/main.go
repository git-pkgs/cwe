// Command gen regenerates cwe.json from the MITRE CWE XML download.
//
// Each entry in the output carries the weakness name, its short description,
// and its View-1400 ("Comprehensive Categorization for Software Assurance
// Trends") category label. Deprecated weaknesses are dropped. The output is
// deterministic: keys are sorted and there is no insignificant whitespace, so
// a re-run against the same XML produces a byte-identical file.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

const (
	source = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
	// maxXML caps both the HTTP body and the decompressed XML entry so a
	// compromised or redirected download cannot OOM the Actions runner. The
	// real cwec_latest.xml is ~15 MB; 100 MB leaves room for growth.
	maxXML = 100 << 20
)

type entry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category,omitempty"`
}

// catalog is the subset of the MITRE XML the generator reads. The XML uses a
// default namespace which encoding/xml would otherwise require on every field
// tag; it is stripped from the raw bytes before Unmarshal so plain local
// names work here.
type catalog struct {
	Weaknesses []weakness `xml:"Weaknesses>Weakness"`
	Categories []category `xml:"Categories>Category"`
}

type weakness struct {
	ID          string `xml:"ID,attr"`
	Name        string `xml:"Name,attr"`
	Status      string `xml:"Status,attr"`
	Description string `xml:"Description"`
}

type category struct {
	Name    string   `xml:"Name,attr"`
	Members []member `xml:"Relationships>Has_Member"`
}

type member struct {
	CWEID  string `xml:"CWE_ID,attr"`
	ViewID string `xml:"View_ID,attr"`
}

func main() {
	out := flag.String("o", "cwe.json", "output path")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	raw, err := fetch()
	if err != nil {
		return err
	}
	// encoding/xml has no way to say "ignore the default namespace", so
	// stripping the xmlns attribute is the least-noisy way to decode with
	// plain local names.
	raw = regexp.MustCompile(` xmlns="[^"]+"`).ReplaceAll(raw, nil)
	var cat catalog
	if err := xml.Unmarshal(raw, &cat); err != nil {
		return fmt.Errorf("parse xml: %w", err)
	}

	catOf := map[string]string{}
	for _, c := range cat.Categories {
		label, ok := strings.CutPrefix(c.Name, "Comprehensive Categorization: ")
		if !ok {
			continue
		}
		for _, m := range c.Members {
			if m.ViewID == "1400" {
				catOf["CWE-"+m.CWEID] = label
			}
		}
	}

	ws := regexp.MustCompile(`\s+`)
	entries := map[string]entry{}
	for _, w := range cat.Weaknesses {
		if w.Status == "Deprecated" {
			continue
		}
		id := "CWE-" + w.ID
		entries[id] = entry{
			Name:        w.Name,
			Description: strings.TrimSpace(ws.ReplaceAllString(w.Description, " ")),
			Category:    catOf[id],
		}
	}

	data, err := marshalSorted(entries)
	if err != nil {
		return err
	}
	const perm = 0o644
	return os.WriteFile(out, data, perm)
}

func fetch() ([]byte, error) {
	resp, err := http.Get(source)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: %s", source, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxXML))
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".xml") {
			continue
		}
		if f.UncompressedSize64 > maxXML {
			return nil, fmt.Errorf("xml entry too large: %d bytes", f.UncompressedSize64)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		return io.ReadAll(io.LimitReader(rc, maxXML))
	}
	return nil, fmt.Errorf("no .xml in %s", source)
}

// marshalSorted encodes m as a JSON object with keys in sorted order and no
// insignificant whitespace, so a re-run against the same XML produces a
// zero-byte diff. HTML escaping is disabled: descriptions can legitimately
// contain angle brackets and there is no HTML context here.
func marshalSorted(m map[string]entry) ([]byte, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		if err := enc.Encode(m[k]); err != nil {
			return nil, err
		}
		// Encoder.Encode appends a newline; drop it.
		buf.Truncate(buf.Len() - 1)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
