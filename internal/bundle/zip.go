package bundle

import (
	"archive/zip"
	"compress/bzip2"
	"errors"
	"fmt"
	"io"
	"strings"
)

func init() {
	// PHP's libzip inflates bzip2 entries; the exporter never writes them,
	// but the two verifiers must read the same archives. LZMA and other
	// methods are not in Go's standard library and are treated as an
	// extraction failure, which is also what a libzip built without them
	// reports (observed on Ubuntu's PHP 8.3).
	zip.RegisterDecompressor(12, func(r io.Reader) io.ReadCloser {
		return io.NopCloser(bzip2.NewReader(r))
	})
}

// zipReader serves the files a PHP extraction of the archive would have
// left on disk, keyed by their normalised names.
type zipReader struct {
	path  string
	rc    *zip.ReadCloser
	files map[string]*zip.File
}

func openZip(path string) (*zipReader, *HardError) {
	rc, err := zip.OpenReader(path)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, &HardError{Message: fmt.Sprintf("could not open zip [%s]", path), Code: 1}
	}
	files, ok := extract(rc.File)
	if !ok {
		rc.Close()
		return nil, &HardError{Message: fmt.Sprintf("could not extract zip [%s]", path), Code: 1}
	}
	return &zipReader{path: path, rc: rc, files: files}, nil
}

// extract replays ZipArchive::extractTo in memory: entries in central
// directory order, each name normalised as PHP does, directories created
// on the way, a later file replacing an earlier one, and any collision
// between a file and a directory failing the whole extraction. Every entry
// is also inflated once so that a bad CRC, an unsupported method or an
// encrypted entry fails here, before anything is verified, as it does in
// PHP.
func extract(entries []*zip.File) (map[string]*zip.File, bool) {
	dirs := map[string]bool{}
	files := map[string]*zip.File{}

	mkdirAll := func(dir string) bool {
		if dir == "" {
			return true
		}
		parts := strings.Split(dir, "/")
		for i := range parts {
			prefix := strings.Join(parts[:i+1], "/")
			if files[prefix] != nil {
				return false
			}
			dirs[prefix] = true
		}
		return true
	}

	for _, f := range entries {
		name, ok := phpZipPath(f.Name)
		if !ok {
			return nil, false
		}
		if strings.HasSuffix(name, "/") {
			if !mkdirAll(strings.TrimSuffix(name, "/")) {
				return nil, false
			}
			continue
		}
		dir := ""
		if i := strings.LastIndexByte(name, '/'); i >= 0 {
			dir = name[:i]
		}
		if !mkdirAll(dir) {
			return nil, false
		}
		if dirs[name] {
			return nil, false
		}
		if !entryReadable(f) {
			return nil, false
		}
		files[name] = f
	}
	return files, true
}

// entryReadable inflates an entry to nothing, so a bad checksum, an
// unsupported compression method, an encrypted entry or an oversized entry
// fails the extraction the way libzip's fails PHP's.
func entryReadable(f *zip.File) bool {
	if f.Flags&0x1 != 0 {
		return false
	}
	r, err := f.Open()
	if err != nil {
		return false
	}
	defer r.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(r, MaxEntryBytes+1))
	return err == nil && n <= MaxEntryBytes
}

// phpZipPath normalises a zip entry name as PHP's ZipArchive::extractTo
// does on Linux: virtual_file_ex collapses repeated slashes and resolves
// "." and ".." (a leading ".." in a relative name survives that step, an
// absolute name loses its leading slash), and php_zip_make_relative_path
// then drops everything up to the rightmost slash that follows a "." or
// ":" character, which is what removes the surviving "../" prefixes. The
// second result is false when the name normalises to nothing, which makes
// PHP's extraction fail.
func phpZipPath(name string) (string, bool) {
	absolute := strings.HasPrefix(name, "/")
	var stack []string
	for _, c := range strings.Split(name, "/") {
		switch c {
		case "", ".":
		case "..":
			if len(stack) > 0 && stack[len(stack)-1] != ".." {
				stack = stack[:len(stack)-1]
			} else if !absolute {
				stack = append(stack, "..")
			}
		default:
			stack = append(stack, c)
		}
	}
	p := strings.Join(stack, "/")
	if p == "" {
		return "", false
	}
	if strings.HasSuffix(name, "/") {
		p += "/"
	}
	if absolute {
		return p, true
	}
	for i := len(p) - 1; i >= 2; i-- {
		if p[i] == '/' && (p[i-1] == '.' || p[i-1] == ':') {
			p = p[i+1:]
			break
		}
	}
	// What survives is written as a file or directory under the temporary
	// directory. A bare ".." names the parent directory itself, which
	// cannot be opened for writing, so PHP's extraction fails on it.
	if p == "" || p == "/" || p == ".." {
		return "", false
	}
	return p, true
}

// lookupName turns the name verify.php would pass to is_file into the key
// PHP's file system would resolve it to: repeated slashes and "."
// components vanish, and a trailing slash can never name a file.
func lookupName(name string) (string, bool) {
	if strings.HasSuffix(name, "/") || strings.HasSuffix(name, "/.") {
		return "", false
	}
	var parts []string
	for _, c := range strings.Split(name, "/") {
		if c == "" || c == "." {
			continue
		}
		parts = append(parts, c)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, "/"), true
}

func (z *zipReader) file(name string) *zip.File {
	key, ok := lookupName(name)
	if !ok {
		return nil
	}
	return z.files[key]
}

func (z *zipReader) IsFile(name string) bool { return z.file(name) != nil }

func (z *zipReader) Open(name string) (io.ReadCloser, error) {
	f := z.file(name)
	if f == nil {
		return nil, &HardError{Message: fmt.Sprintf("could not read [%s]", name), Code: 1}
	}
	r, err := f.Open()
	if err != nil {
		return nil, &HardError{Message: fmt.Sprintf("could not read [%s]", name), Code: 1}
	}
	return r, nil
}

func (z *zipReader) ReadWhole(name string) ([]byte, error) {
	f := z.file(name)
	if f == nil {
		return nil, nil
	}
	return readCapped(name, func() (io.ReadCloser, error) { return f.Open() })
}

func (z *zipReader) Close() error { return z.rc.Close() }
