package internal

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonSeekerReader hides the Seeker implementation of the wrapped reader, so that
// the buffering path of ResetReader is tested.
type nonSeekerReader struct {
	reader io.Reader
}

func (r *nonSeekerReader) Read(b []byte) (int, error) {
	return r.reader.Read(b)
}

func resetReaderTestInputs() map[string]func([]byte) io.Reader {
	return map[string]func([]byte) io.Reader{
		"seeker": func(data []byte) io.Reader {
			return bytes.NewReader(data)
		},
		"buffered": func(data []byte) io.Reader {
			return &nonSeekerReader{reader: bytes.NewReader(data)}
		},
	}
}

func TestResetReaderReplaysFromBeginning(t *testing.T) {
	for name, newReader := range resetReaderTestInputs() {
		t.Run(name, func(t *testing.T) {
			input := []byte("0123456789")
			reader := NewResetReader(newReader(input))
			buffer := make([]byte, 4)

			n, err := reader.Read(buffer)
			require.NoError(t, err)
			assert.Equal(t, 4, n)
			assert.Equal(t, "0123", string(buffer))

			// A reset rewinds a partially read stream to the beginning.
			_, err = reader.Reset()
			require.NoError(t, err)

			read, err := io.ReadAll(reader)
			require.NoError(t, err)
			assert.Equal(t, string(input), string(read))
		})
	}
}

func TestResetReaderRepeatedResets(t *testing.T) {
	for name, newReader := range resetReaderTestInputs() {
		t.Run(name, func(t *testing.T) {
			input := []byte("abcdefghij")
			reader := NewResetReader(newReader(input))

			// Simulate several candidates that consume a different amount of the
			// stream and are rewound in between.
			for _, partial := range []int{3, 7, 1} {
				_, err := reader.Read(make([]byte, partial))
				require.NoError(t, err)
				_, err = reader.Reset()
				require.NoError(t, err)

				read, err := io.ReadAll(reader)
				require.NoError(t, err)
				assert.Equal(t, string(input), string(read))

				_, err = reader.Reset()
				require.NoError(t, err)
			}
		})
	}
}

func TestResetReaderResetFromOriginalOffset(t *testing.T) {
	// A ResetReader that starts in the middle of a seekable stream has to return
	// to the position it was created at, not to the beginning of the stream.
	stream := bytes.NewReader([]byte("0123456789"))
	_, err := stream.Seek(3, io.SeekStart)
	require.NoError(t, err)

	reader := NewResetReader(stream)
	read, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "3456789", string(read))

	_, err = reader.Reset()
	require.NoError(t, err)
	read, err = io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "3456789", string(read))
}

func TestResetReaderNonBuffering(t *testing.T) {
	// Without buffering, the data read must not be kept in memory and the stream
	// cannot be rewound at all.
	reader := NewNonBufferingResetReader(bytes.NewReader([]byte("0123456789")))

	_, err := reader.Reset()
	require.Error(t, err)

	read, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, "0123456789", string(read))
	assert.Nil(t, reader.buffered)
}

func TestResetReaderDisableBuffering(t *testing.T) {
	for name, newReader := range resetReaderTestInputs() {
		t.Run(name, func(t *testing.T) {
			input := []byte("0123456789")
			reader := NewResetReader(newReader(input))

			_, err := reader.Read(make([]byte, 5))
			require.NoError(t, err)
			_, err = reader.Reset()
			require.NoError(t, err)

			// Replay a part of the buffered data, then disable buffering.
			_, err = reader.Read(make([]byte, 2))
			require.NoError(t, err)
			reader.DisableBuffering()

			// Resetting is not allowed anymore.
			_, err = reader.Reset()
			require.Error(t, err)

			// Reading still returns the complete stream; the data that was not
			// replayed yet stays available and the remaining data is read from the
			// underlying reader.
			read, err := io.ReadAll(reader)
			require.NoError(t, err)
			assert.Equal(t, "23456789", string(read))

			// The buffered data has been released.
			assert.Nil(t, reader.buffered)
		})
	}
}
