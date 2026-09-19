package bundle

import (
	"bufio"
	"io"
)

// Lines reads a file one line at a time, as verify.php's read_lines does
// with fgets: a line ends at LF, the last line needs no LF, and every
// trailing CR and LF is stripped (rtrim($line, "\r\n")). Line numbers are
// zero-based here and the verifier adds one for its messages, as PHP does.
// Memory is bounded by MaxLineBytes rather than by the file.
type Lines struct {
	r      *bufio.Reader
	line   []byte
	number int
	err    error
	done   bool
}

// NewLines wraps r.
func NewLines(r io.Reader) *Lines {
	return &Lines{r: bufio.NewReaderSize(r, 1<<16), number: -1}
}

// Next advances to the next line. It returns false at the end of the file
// or on an error; Err distinguishes the two.
func (l *Lines) Next() bool {
	if l.done {
		return false
	}
	l.line = l.line[:0]
	for {
		chunk, err := l.r.ReadSlice('\n')
		if len(l.line)+len(chunk) > MaxLineBytes {
			l.err = ErrLineTooLong
			l.done = true
			return false
		}
		l.line = append(l.line, chunk...)
		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			l.done = true
			if len(l.line) == 0 {
				return false
			}
			break
		}
		l.err = err
		l.done = true
		return false
	}
	end := len(l.line)
	for end > 0 && (l.line[end-1] == '\n' || l.line[end-1] == '\r') {
		end--
	}
	l.line = l.line[:end]
	l.number++
	return true
}

// Line is the current line without its line ending. The slice is reused
// by the next call to Next.
func (l *Lines) Line() []byte { return l.line }

// Number is the zero-based index of the current line.
func (l *Lines) Number() int { return l.number }

// Err is the error that stopped Next, if any.
func (l *Lines) Err() error { return l.err }
