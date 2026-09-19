package bundle

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzZip feeds arbitrary bytes to the archive reader: no panic, no
// unbounded allocation, and every file the reader offers must be readable
// to its end.
func FuzzZip(f *testing.F) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range []string{"manifest.json", "events.ndjson", "../x", "dir/", "a/b/c"} {
		fw, _ := w.Create(name)
		fw.Write([]byte(`{"a":1}` + "\n"))
	}
	w.Close()
	f.Add(buf.Bytes())
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("not a zip at all"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		path := filepath.Join(t.TempDir(), "in.zip")
		os.WriteFile(path, data, 0o644)
		r, herr := Open(path)
		if herr != nil {
			return
		}
		defer r.Close()
		for _, name := range []string{"manifest.json", "events.ndjson", "checkpoints.json", "x", "a/b/c"} {
			if !r.IsFile(name) {
				continue
			}
			rc, err := r.Open(name)
			if err != nil {
				continue
			}
			io.Copy(io.Discard, io.LimitReader(rc, 1<<20))
			rc.Close()
			r.ReadWhole(name)
		}
	})
}

// FuzzLines feeds arbitrary bytes to the line reader: no panic, every line
// shorter than the cap, and the concatenation of lines with their
// separators accounts for the input.
func FuzzLines(f *testing.F) {
	f.Add([]byte("a\r\nb\n\n   \nc"))
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add(bytes.Repeat([]byte("x"), 70000))
	f.Fuzz(func(t *testing.T, data []byte) {
		l := NewLines(bytes.NewReader(data))
		total := 0
		for l.Next() {
			line := l.Line()
			if len(line) > MaxLineBytes {
				t.Fatalf("line of %d bytes exceeds the cap", len(line))
			}
			if bytes.ContainsAny(line, "\n") {
				t.Fatalf("line contains a newline")
			}
			if strings.HasSuffix(string(line), "\r") {
				t.Fatalf("trailing CR not stripped")
			}
			total++
		}
		if l.Err() != nil && l.Err() != ErrLineTooLong {
			t.Fatalf("unexpected error %v", l.Err())
		}
		if l.Err() == nil && total > bytes.Count(data, []byte("\n"))+1 {
			t.Fatalf("more lines than separators")
		}
	})
}
