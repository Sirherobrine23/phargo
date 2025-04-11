package phargo

import "io"

// Parsed PHAR-file
type Phar struct {
	Menifest  *Manifest
	Signature *Signature
	Files     []*File
}

// readerAtAdapter wraps an io.ReaderAt to implement io.Reader.
type readerAtAdapter struct {
	reader io.ReaderAt
	offset int64 // Current read position
}

// Read implements the io.Reader interface.
func (r *readerAtAdapter) Read(p []byte) (n int, err error) {
	// Use ReadAt with the current offset.
	n, err = r.reader.ReadAt(p, r.offset)
	// Advance the offset for the next read.
	r.offset += int64(n)
	// Return bytes read and any error (including io.EOF).
	return n, err
}

// NewReaderFromReaderAt creates an io.Reader from an io.ReaderAt, starting at offset 0.
func newReaderFromReaderAt(r io.ReaderAt) io.Reader {
	return &readerAtAdapter{reader: r, offset: 0}
}
func newReaderFromReaderAtOffset(r io.ReaderAt, offset int64) io.Reader {
	return &readerAtAdapter{reader: r, offset: offset}
}
