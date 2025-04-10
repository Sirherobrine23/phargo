package phargo

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

const (
	ManifestBitmapPermsion = 0x000001FF
	ManifestBitmapDeflate  = 0x00001000
	ManifestBitmapBzip2    = 0x00002000

	CompressionMask    = 0xF000
	entCOMPRESSED_NONE = 0x00000000
	entCOMPRESSED_GZ   = 0x00001000
	entCOMPRESSED_BZ2  = 0x00002000
)

type File struct {
	Filename         string
	Timestamp        time.Time
	Size             int64
	Flags            uint32
	SizeUncompressed int64
	SizeCompressed   int64
	CRC              uint32
	MetaSerialized   []byte

	metadataOpen        io.ReaderAt
	dataOffset, dataLen int64
}

// Return file reader with descompression if compressed
func (file File) Open() (io.ReadCloser, error) {
	r := io.LimitReader(newReaderFromReaderAtOffset(file.metadataOpen, file.dataOffset), file.dataLen)
	switch {
	case file.Flags&entCOMPRESSED_GZ > 0:
		return gzip.NewReader(r)
	case file.Flags&entCOMPRESSED_BZ2 > 0:
		return io.NopCloser(bzip2.NewReader(r)), nil
	default:
		return io.NopCloser(r), nil
	}
}

// Parse file entry manifest to struct
//
// PHP Docs: https://www.php.net/manual/en/phar.fileformat.manifestfile.php
func ParseEntryManifest(r io.ReaderAt, offset int64) (*File, int64, error) {
	buff := make([]byte, 28)
	if n, err := r.ReadAt(buff[:4], offset); err != nil {
		return nil, offset + int64(n), fmt.Errorf("cannot get filename size: %s", err)
	}
	filenameSize := binary.LittleEndian.Uint32(buff[:4])
	buff = bytes.Join([][]byte{buff, make([]byte, filenameSize)}, []byte{})
	if n, err := r.ReadAt(buff, offset); err != nil {
		return nil, offset + int64(n), fmt.Errorf("cannot get meta size: %s", err)
	}
	offset += int64(len(buff))
	filenameSize += 4
	name := path.Clean(string(buff[4:filenameSize]))
	var eb struct {
		SizeUncompressed uint32
		Timestamp        uint32
		SizeCompressed   uint32
		CRC              uint32
		Flags            uint32
		MetaLength       uint32
	}
	binary.Read(bytes.NewReader(buff[filenameSize:]), binary.LittleEndian, &eb)
	buff = buff[filenameSize+24:]

	// Make buff to Meta
	if eb.MetaLength > 0 {
		buff = make([]byte, eb.MetaLength)
		if n, err := r.ReadAt(buff, offset); err != nil {
			return nil, offset + int64(n), fmt.Errorf("cannot get meta length: %s", err)
		}
	}

	newManifest := &File{
		Filename:         name,
		SizeUncompressed: int64(eb.SizeUncompressed),
		Timestamp:        time.Unix(int64(eb.Timestamp), 0),
		SizeCompressed:   int64(eb.SizeCompressed),
		CRC:              eb.CRC,
		Flags:            eb.Flags,
		MetaSerialized:   buff[:eb.MetaLength],
		metadataOpen:     r,
	}

	// Append read file size to open
	newManifest.dataLen = newManifest.SizeUncompressed
	if newManifest.Flags&CompressionMask > 0 {
		newManifest.dataLen = newManifest.SizeCompressed
	}

	return newManifest, offset + int64(len(buff)), nil
}

type Manifest struct {
	Length        uint32
	EntitiesCount uint32
	Version       string
	Flags         uint32
	Alias         []byte
	AliasLength   uint32
	Metadata      []byte
	IsSigned      bool
}

// Parse phar menifest
//
// PHP Docs: https://www.php.net/manual/en/phar.fileformat.phar.php
func ParseManifest(r io.ReaderAt) (*Manifest, int64, error) {
	offset, err := getOffset(r, 200, "__HALT_COMPILER(); ?>")
	if err != nil {
		return nil, 0, err
	}

	fistParams := make([]byte, 18)
	if n, err := r.ReadAt(fistParams, offset); err != nil {
		return nil, offset + int64(n), fmt.Errorf("cannot get initials params: %s", err)
	}
	offset += 18

	newManifest := &Manifest{
		Length:        binary.LittleEndian.Uint32(fistParams[:4]),
		EntitiesCount: binary.LittleEndian.Uint32(fistParams[4:8]),
		Version:       fmt.Sprintf("%d.%d.%d", (binary.LittleEndian.Uint16(fistParams[8:10])<<12)>>12, ((binary.LittleEndian.Uint16(fistParams[8:10])>>4)<<12)>>12, ((binary.LittleEndian.Uint16(fistParams[8:10])>>8)<<12)>>12),
		Flags:         binary.LittleEndian.Uint32(fistParams[10:14]),
		AliasLength:   binary.LittleEndian.Uint32(fistParams[14:]),
	}
	newManifest.IsSigned = newManifest.Flags&0x10000 > 0

	newManifest.Alias = make([]byte, newManifest.AliasLength)
	if n, err := r.ReadAt(newManifest.Alias, offset); err != nil {
		return nil, offset + int64(n), err
	}
	offset += int64(newManifest.AliasLength)

	metaLen := make([]byte, 4)
	if n, err := r.ReadAt(metaLen, offset); err != nil {
		return nil, offset + int64(n), err
	}
	offset += 4
	
	MetaLength := binary.LittleEndian.Uint32(metaLen)
	if MetaLength > 0 {
		newManifest.Metadata = make([]byte, MetaLength)
		if n, err := r.ReadAt(newManifest.Metadata, offset); err != nil {
			return nil, offset + int64(n), err
		}
		offset += int64(MetaLength)
	}
	return newManifest, offset, nil
}

func getOffset(f io.ReaderAt, bufSize int64, haltCompiler string) (int64, error) {
	currentPossion, buffer, before := int64(0), make([]byte, bufSize), make([]byte, bufSize)
	for {
		n, err := f.ReadAt(buffer, currentPossion)
		if err != nil {
			return 0, errors.New("can't find haltCompiler: " + err.Error())
		}

		search := append(before, buffer...)
		index := strings.Index(string(search), haltCompiler)

		if index >= 0 {
			offset := currentPossion + int64(index) - bufSize + int64(len(haltCompiler))
			if index+len(haltCompiler) >= len(search) {
				return 0, errors.New("unexpected end of file")
			}

			//optional \r\n or \n
			var nextChar = search[index+len(haltCompiler)]
			var nextNextChar = search[index+len(haltCompiler)+1]
			if nextChar == '\r' && nextNextChar == '\n' {
				offset += 2
			}
			if nextChar == '\n' {
				offset++
			}

			return offset, nil
		}

		currentPossion += int64(n)
		copy(before, buffer)
	}
}
