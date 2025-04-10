package phargo

import (
	"os"
	"testing"
)

func TestSimple(t *testing.T) {
	osFile, err := os.Open("./testdata/simple.phar")
	if err != nil {
		t.Skip(err)
		return
	}

	file, err := NewReaderFromFile(osFile)
	if err != nil {
		t.Error("Got error", err)
		return
	}

	if len(file.Files) != 2 {
		t.Error("Not 2 files")
		return
	}

	if file.Files[0].Filename != "1.txt" {
		t.Error("Wrong 1 file name")
		return
	}

	f, _ := file.Files[0].Open()
	buff := make([]byte, 4)
	f.Read(buff)
 	if string(buff) != "ASDF" {
  	t.Error("Wrong 0 file content")
		return
  }


	if file.Files[1].Filename != "index.php" {
		t.Error("Wrong 2 file name")
		return
	}

	f, _ = file.Files[1].Open()
	f.Read(buff)
	if string(buff) != "ZXCV" {
		t.Error("Wrong 1 file content")
		return
	}

	if string(file.Menifest.Metadata) != "a:1:{s:1:\"a\";i:123;}" {
		t.Error("Wrong metadata")
		return
	}
}

func TestBadHash(t *testing.T) {
	osFile, err := os.Open("./testdata/bad_hash.phar")
	if err != nil {
		t.Skip(err)
		return
	}

	if _, err = NewReaderFromFile(osFile); err == nil {
		t.Error("Should get error")
		return
	}
}
