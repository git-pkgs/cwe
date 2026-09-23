# cwe

Go library for looking up MITRE CWE (Common Weakness Enumeration) entries by ID.

The catalogue is embedded at build time and covers every non-deprecated weakness with its name, short description, and [View-1400](https://cwe.mitre.org/data/definitions/1400.html) category. A monthly workflow regenerates it from `cwec_latest.xml.zip` and opens a PR when it changes.

## Installation

```
go get github.com/git-pkgs/cwe
```

## Usage

```go
import "github.com/git-pkgs/cwe"

id, e, ok := cwe.Lookup("79")
// id = "CWE-79"
// e.Name = "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
// e.Category = "Injection"

for _, label := range cwe.Categories() {
    fmt.Println(cwe.CategoryID(label), label, len(cwe.InCategory(label)))
}
// CWE-1396 Access Control 60
// CWE-1397 Comparison 13
// ...

cwe.CategoryOf("CWE-352") // "CWE-1411"
```

`Lookup` accepts `"CWE-79"`, `"cwe-79"`, or `"79"` and returns the canonical `CWE-` form.

## Regenerating the catalogue

```
go generate ./...
```

fetches the latest XML from cwe.mitre.org and rewrites `cwe.json`. The output is deterministic (sorted keys, no whitespace), so a re-run against unchanged XML produces no diff.

## License

[MIT](LICENSE). The CWE catalogue is © The MITRE Corporation and used under its [terms of use](https://cwe.mitre.org/about/termsofuse.html).
