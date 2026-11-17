// Package internal contains internal methods and constants.
package internal

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/ProtonMail/gopenpgp/v3/constants"
)

var nl []byte = []byte("\n")
var rnl []byte = []byte("\r\n")

func Canonicalize(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", "\r\n")
}

func CanonicalizeBytes(text []byte) []byte {
	return bytes.ReplaceAll(bytes.ReplaceAll(text, rnl, nl), nl, rnl)
}

func TrimEachLine(text string) string {
	lines := strings.Split(text, "\n")

	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t\r")
	}

	return strings.Join(lines, "\n")
}

func TrimEachLineBytes(text []byte) []byte {
	lines := bytes.Split(text, nl)

	for i := range lines {
		lines[i] = bytes.TrimRight(lines[i], " \t\r")
	}

	return bytes.Join(lines, nl)
}

// ArmorHeaders is a map of default armor headers.
var ArmorHeaders = map[string]string{}

func init() {
	if constants.ArmorHeaderEnabled {
		ArmorHeaders = map[string]string{
			"Version": constants.ArmorHeaderVersion,
			"Comment": constants.ArmorHeaderComment,
		}
	}
}

// ResetReader is a reader that can be reset to the beginning of the stream.
//
// For readers that implement io.Seeker (e.g. bytes.Reader) a reset simply seeks
// back to the start, so that no data has to be kept in memory. For all other
// readers the data read so far is buffered once and replayed after a reset.
// Only data that has actually been read is buffered; once the decryption
// candidate has been selected, DisableBuffering releases the buffered
// ciphertext so that reading the plaintext stays streaming.
type ResetReader struct {
	reader     io.Reader
	seeker     io.Seeker // non-nil if the stream can be rewound by seeking
	start      int64     // position of the first byte of the stream
	buffered   []byte    // bytes read since the beginning of the stream
	pos        int       // current read position in buffered / on the stream
	bufferData bool      // whether read data is kept for replaying it
	resettable bool      // whether a Reset is still possible
}

// NewResetReader creates a new ResetReader with the default state.
// Data read from a non-seekable stream is buffered, so that it can be replayed
// after a Reset.
func NewResetReader(reader io.Reader) *ResetReader {
	return newResetReader(reader, true)
}

// NewNonBufferingResetReader creates a ResetReader that keeps no copy of the
// read data and cannot be reset. It is intended for callers that know that the
// stream is read in a single pass, e.g. when only a single decryption candidate
// is tried, to avoid buffering a potentially large ciphertext.
func NewNonBufferingResetReader(reader io.Reader) *ResetReader {
	return newResetReader(reader, false)
}

func newResetReader(reader io.Reader, bufferData bool) *ResetReader {
	rr := &ResetReader{
		reader:     reader,
		bufferData: bufferData,
		resettable: bufferData,
	}
	if seeker, ok := reader.(io.Seeker); ok {
		// Remember the current position, so that a reset returns to the
		// beginning of the stream as seen by this reader.
		if start, err := seeker.Seek(0, io.SeekCurrent); err == nil {
			rr.seeker = seeker
			rr.start = start
		}
	}
	return rr
}

func (rr *ResetReader) Read(b []byte) (n int, err error) {
	if rr.pos < len(rr.buffered) {
		// Replay data that was read before the last reset.
		n = copy(b, rr.buffered[rr.pos:])
		rr.pos += n
		if !rr.bufferData && rr.pos == len(rr.buffered) {
			// Buffering is disabled and all buffered data has been replayed;
			// release it, the stream continues from the underlying reader.
			rr.buffered = nil
			rr.pos = 0
		}
		return n, nil
	}
	n, err = rr.reader.Read(b)
	if rr.bufferData && rr.seeker == nil {
		rr.buffered = append(rr.buffered, b[:n]...)
	}
	rr.pos += n
	return
}

// DisableBuffering disables the internal buffering and releases the data that
// was already replayed. After the disable, a Reset is not allowed anymore.
func (rr *ResetReader) DisableBuffering() {
	rr.bufferData = false
	rr.resettable = false
	if rr.pos >= len(rr.buffered) {
		// All buffered data has been replayed, so it is not needed anymore.
		rr.buffered = nil
		rr.pos = 0
	}
}

// Reset resets the reader to the beginning of the stream.
func (rr *ResetReader) Reset() (io.Reader, error) {
	if !rr.resettable {
		return nil, errors.New("reset not possible if buffering is disabled")
	}
	if rr.seeker != nil {
		if _, err := rr.seeker.Seek(rr.start, io.SeekStart); err != nil {
			return nil, err
		}
	}
	rr.pos = 0
	return rr, nil
}

type noOpWriteCloser struct {
	writer io.Writer
}

// NewNoOpWriteCloser creates a WriteCloser form a Writer that performs no operation on close.
func NewNoOpWriteCloser(writer io.Writer) io.WriteCloser {
	return &noOpWriteCloser{
		writer,
	}
}

func (w *noOpWriteCloser) Write(p []byte) (n int, err error) {
	return w.writer.Write(p)
}

func (w *noOpWriteCloser) Close() error {
	return nil
}
