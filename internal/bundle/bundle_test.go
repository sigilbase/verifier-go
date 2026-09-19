package bundle

import (
	"archive/zip"
	"bytes"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every expectation here was observed by running verify.php under PHP 8.3
// on Ubuntu and PHP 8.4 on Windows against the same archives (the
// scratchpad zip probes in this session); FORMAT.md records the rules.

type entry struct {
	name string
	data string // "" with dir true makes a directory entry
	dir  bool
}

func writeZip(t *testing.T, entries []entry) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		if e.dir {
			if _, err := w.Create(strings.TrimSuffix(e.name, "/") + "/"); err != nil {
				t.Fatal(err)
			}
			continue
		}
		f, err := w.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readAll(t *testing.T, r Reader, name string) string {
	t.Helper()
	data, err := r.ReadWhole(name)
	if err != nil {
		t.Fatalf("ReadWhole(%s): %v", name, err)
	}
	return string(data)
}

func TestPHPZipPath(t *testing.T) {
	cases := map[string]string{
		"events.ndjson":         "events.ndjson",
		"./events.ndjson":       "events.ndjson",
		"../events.ndjson":      "events.ndjson",
		"../../events.ndjson":   "events.ndjson",
		"/events.ndjson":        "events.ndjson",
		"//events.ndjson":       "events.ndjson",
		"sub/../events.ndjson":  "events.ndjson",
		"a/../../events.ndjson": "events.ndjson",
		"../a/b":                "a/b",
		"a//b":                  "a/b",
		"a/./b":                 "a/b",
		"dir/":                  "dir/",
		"../dir/":               "dir/",
		"certificates/x.pdf":    "certificates/x.pdf",
		"certificates\\x.pdf":   "certificates\\x.pdf",
		"x./events.ndjson":      "events.ndjson", // the "." before a slash quirk of php_zip_make_relative_path
		"c:/events.ndjson":      "events.ndjson",
		"/../events.ndjson":     "events.ndjson",
		"a/b/../../c/./d/":      "c/d/",
		"deep/dir/file.bin":     "deep/dir/file.bin",
		"trailing/dot./x":       "x",
		"a/b/../../../../c":     "c",
		"./":                    "",
		".":                     "",
		"..":                    "",
		"/":                     "",
		"dir/..":                "",
		"":                      "",
	}
	for in, want := range cases {
		got, ok := phpZipPath(in)
		if want == "" {
			if ok {
				t.Errorf("phpZipPath(%q) = %q, want failure", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("phpZipPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestLastEntryWins(t *testing.T) {
	path := writeZip(t, []entry{{name: "events.ndjson", data: "first"}, {name: "events.ndjson", data: "second"}})
	r, herr := Open(path)
	if herr != nil {
		t.Fatal(herr)
	}
	defer r.Close()
	if got := readAll(t, r, "events.ndjson"); got != "second" {
		t.Errorf("duplicate entry: read %q, PHP reads the last one", got)
	}
}

func TestParentAndAbsoluteEntriesShadow(t *testing.T) {
	for _, shadow := range []string{"../events.ndjson", "/events.ndjson", "sub/../events.ndjson", "x./events.ndjson"} {
		path := writeZip(t, []entry{{name: "events.ndjson", data: "real"}, {name: shadow, data: "shadow"}})
		r, herr := Open(path)
		if herr != nil {
			t.Fatalf("%s: %v", shadow, herr)
		}
		if got := readAll(t, r, "events.ndjson"); got != "shadow" {
			t.Errorf("%s after the real entry: read %q, PHP reads the later entry", shadow, got)
		}
		r.Close()
		path = writeZip(t, []entry{{name: shadow, data: "shadow"}, {name: "events.ndjson", data: "real"}})
		r, herr = Open(path)
		if herr != nil {
			t.Fatalf("%s: %v", shadow, herr)
		}
		if got := readAll(t, r, "events.ndjson"); got != "real" {
			t.Errorf("%s before the real entry: read %q", shadow, got)
		}
		r.Close()
	}
	path := writeZip(t, []entry{{name: "../events.ndjson", data: "only"}})
	r, herr := Open(path)
	if herr != nil {
		t.Fatal(herr)
	}
	defer r.Close()
	if !r.IsFile("events.ndjson") {
		t.Error("a parent-path entry alone is extracted as the plain file in PHP")
	}
}

func TestDirectoryCollisionsFailExtraction(t *testing.T) {
	cases := [][]entry{
		{{name: "manifest.json", data: "{}"}, {name: "manifest.json/", dir: true}},
		{{name: "manifest.json/", dir: true}, {name: "manifest.json", data: "{}"}},
		{{name: "a", data: "x"}, {name: "a/b", data: "y"}},
		{{name: "a/b", data: "y"}, {name: "a", data: "x"}},
		{{name: "..", data: "x"}},
		{{name: "dir/..", data: "x"}},
	}
	for i, c := range cases {
		path := writeZip(t, c)
		r, herr := Open(path)
		if herr == nil || herr.Code != 1 || !strings.HasPrefix(herr.Message, "could not extract zip [") {
			t.Errorf("case %d: got %v, want extraction failure with code 1", i, herr)
		}
		if r != nil {
			r.Close()
		}
	}
}

func TestUnrelatedEntriesAndFoldersAreIgnored(t *testing.T) {
	path := writeZip(t, []entry{
		{name: "manifest.json", data: "{}"},
		{name: "unrelated.txt", data: "hello"},
		{name: "deep/dir/file.bin", data: "x"},
		{name: "certificates\\x.pdf", data: "%PDF"},
		{name: "dir/", dir: true},
		{name: "dir/", dir: true},
	})
	r, herr := Open(path)
	if herr != nil {
		t.Fatal(herr)
	}
	defer r.Close()
	if !r.IsFile("manifest.json") || r.IsFile("events.ndjson") || r.IsFile("dir") || !r.IsFile("deep/dir/file.bin") {
		t.Error("lookup results differ from PHP's is_file on the extracted tree")
	}
	if !r.IsFile("deep//dir/./file.bin") || r.IsFile("deep/dir/file.bin/") {
		t.Error("lookup normalisation differs from the file system's")
	}
	if r.IsFile("certificates/x.pdf") {
		t.Error("a backslash is not a separator on Linux")
	}
	if data, err := r.ReadWhole("events.ndjson"); err != nil || data != nil {
		t.Error("a missing file reads as empty, as (string) file_get_contents does")
	}
	wrapped := writeZip(t, []entry{{name: "bundle/manifest.json", data: "{}"}})
	r2, herr := Open(wrapped)
	if herr != nil {
		t.Fatal(herr)
	}
	defer r2.Close()
	if r2.IsFile("manifest.json") {
		t.Error("a folder-wrapped bundle has no manifest.json at the top")
	}
}

func TestEmptyZipAndNonZip(t *testing.T) {
	path := writeZip(t, nil)
	r, herr := Open(path)
	if herr != nil {
		t.Fatal(herr)
	}
	if r.IsFile("manifest.json") {
		t.Error("empty archive has files")
	}
	r.Close()
	notZip := filepath.Join(t.TempDir(), "x.zip")
	os.WriteFile(notZip, []byte("not a zip"), 0o644)
	if _, herr := Open(notZip); herr == nil || herr.Code != 1 || !strings.HasPrefix(herr.Message, "could not open zip") {
		t.Errorf("non-zip: %v", herr)
	}
	if _, herr := Open(filepath.Join(t.TempDir(), "absent.zip")); herr == nil || herr.Code != 2 || !strings.Contains(herr.Message, "does not exist") {
		t.Errorf("absent: %v", herr)
	}
}

func TestDirectoryBundle(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o644)
	os.MkdirAll(filepath.Join(dir, "certificates"), 0o755)
	os.WriteFile(filepath.Join(dir, "certificates", "a.pdf"), []byte("%PDF"), 0o644)
	r, herr := Open(dir + string(filepath.Separator))
	if herr != nil {
		t.Fatal(herr)
	}
	defer r.Close()
	if !r.IsFile("manifest.json") || !r.IsFile("certificates/a.pdf") || r.IsFile("certificates") || r.IsFile("events.ndjson") {
		t.Error("directory lookups wrong")
	}
	if got := readAll(t, r, "certificates/a.pdf"); got != "%PDF" {
		t.Errorf("read %q", got)
	}
}

func TestCompressionMethodsAndCorruption(t *testing.T) {
	r, herr := Open("testdata/bzip2.zip")
	if herr != nil {
		t.Fatalf("bzip2 archive: %v (PHP's libzip reads it)", herr)
	}
	if !strings.Contains(readAll(t, r, "manifest.json"), "sigilbase-evidence") {
		t.Error("bzip2 entry content")
	}
	r.Close()
	if _, herr := Open("testdata/lzma.zip"); herr == nil || herr.Code != 1 {
		t.Errorf("lzma archive: %v; want extraction failure like a libzip without LZMA", herr)
	}

	// A wrong CRC fails extraction before anything is verified.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "manifest.json", Method: zip.Store}
	f, _ := w.CreateRaw(hdr)
	f.Write([]byte("{}"))
	hdr.CRC32 = crc32.ChecksumIEEE([]byte("xx"))
	hdr.UncompressedSize64 = 2
	hdr.CompressedSize64 = 2
	w.Close()
	path := filepath.Join(t.TempDir(), "crc.zip")
	os.WriteFile(path, buf.Bytes(), 0o644)
	if _, herr := Open(path); herr == nil || herr.Code != 1 || !strings.HasPrefix(herr.Message, "could not extract zip") {
		t.Errorf("bad CRC: %v", herr)
	}

	// An encrypted entry cannot be extracted without a password.
	buf.Reset()
	w = zip.NewWriter(&buf)
	f, _ = w.CreateRaw(&zip.FileHeader{Name: "manifest.json", Method: zip.Store, Flags: 0x1})
	f.Write([]byte("{}"))
	w.Close()
	path = filepath.Join(t.TempDir(), "enc.zip")
	os.WriteFile(path, buf.Bytes(), 0o644)
	if _, herr := Open(path); herr == nil || herr.Code != 1 {
		t.Errorf("encrypted: %v", herr)
	}
}

func TestLines(t *testing.T) {
	input := "a\r\nb\n\n   \n\x0b\nc\r\r\n\x0c\nlast"
	l := NewLines(strings.NewReader(input))
	var got []string
	var blank []bool
	for l.Next() {
		got = append(got, string(l.Line()))
		blank = append(blank, IsBlank(l.Line()))
	}
	if l.Err() != nil {
		t.Fatal(l.Err())
	}
	want := []string{"a", "b", "", "   ", "\x0b", "c", "\x0c", "last"}
	wantBlank := []bool{false, false, true, true, true, false, false, false}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("lines %q, want %q", got, want)
	}
	for i := range want {
		if blank[i] != wantBlank[i] {
			t.Errorf("IsBlank(%q) = %v", want[i], blank[i])
		}
	}
	if l.Number() != 7 {
		t.Errorf("last line number %d, want 7", l.Number())
	}
	empty := NewLines(strings.NewReader(""))
	if empty.Next() {
		t.Error("empty file yields no line")
	}
	one := NewLines(strings.NewReader("\n"))
	if !one.Next() || len(one.Line()) != 0 || one.Next() {
		t.Error("a lone newline is one empty line")
	}
	long := NewLines(io.MultiReader(strings.NewReader(strings.Repeat("x", 100)), strings.NewReader("\n")))
	if !long.Next() || len(long.Line()) != 100 {
		t.Error("line spanning buffer boundaries")
	}
}
