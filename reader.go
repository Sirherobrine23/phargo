package phargo

import (
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

// Parse phar file from [*os.File]
func NewReaderFromFile(file *os.File) (*Phar, error) {
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot get file stats: %s", err)
	}
	return NewReader(file, stat.Size())
}

// Parse phar file
func NewReader(r io.ReaderAt, size int64) (*Phar, error) {
	manifest, offset, err := ParseManifest(r)
	if err != nil {
		return nil, fmt.Errorf("cannot parse manifest: %s", err)
	}

	// Start struct
	filePhar := &Phar{Menifest: manifest, Files: []*File{}}
	if manifest.IsSigned {
		if filePhar.Signature, err = GetSignature(r, size); err != nil {
			return nil, err
		}
	}

	for range manifest.EntitiesCount {
		manifest, newOffset, err := ParseEntryManifest(r, offset)
		if err != nil {
			return nil, fmt.Errorf("cannot get file entry: %s", err)
		}
		offset = newOffset
		filePhar.Files = append(filePhar.Files, manifest)
	}

	for _, file := range filePhar.Files {
		file.dataOffset = offset
		offset += file.dataLen

		f, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("cannot checj CRC to %s: %s", file.Filename, err)
		}
		hash := crc32.New(crc32.MakeTable(0xedb88320))
		if _, err = io.Copy(hash, f); err != nil {
			return nil, fmt.Errorf("fail copy %s content to crc32 hash: %s", file.Filename, err)
		}
		if hash.Sum32() != file.CRC {
			return nil, fmt.Errorf("%s has bad CRC, expect: %d, recived: %d", file.Filename, file.CRC, hash.Sum32())
		}
	}

	return filePhar, nil
}
