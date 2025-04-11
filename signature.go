package phargo

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	SignatureMD5           = SignatureFlag(0x0001)
	SignatureSHA1          = SignatureFlag(0x0002)
	SignatureSHA256        = SignatureFlag(0x0003)
	SignatureSHA512        = SignatureFlag(0x0004)
	SignatureOpenSSL       = SignatureFlag(0x0010)
	SignatureOpenSSLSha256 = SignatureFlag(0x0011)
	SignatureOpenSSLSha512 = SignatureFlag(0x0012)
)

var (
	pharSignatureStubLen = 8
	pharSignatureLenLen  = 4
	pharMaxSignatureLen  = 8 * 1024

	ErrOpenssl          = errors.New("openssl is disabled in this implementation")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrGBMB             = errors.New("can't find GBMB constant at the end")

	sigName = map[SignatureFlag]string{
		SignatureMD5:           "md5",
		SignatureSHA1:          "sha1",
		SignatureSHA256:        "sha256",
		SignatureSHA512:        "sha512",
		SignatureOpenSSL:       "OpenSSL",
		SignatureOpenSSLSha256: "OpenSSL_sha256",
		SignatureOpenSSLSha512: "OpenSSL_sha512",
	}
)

type SignatureFlag uint32

func (sig SignatureFlag) String() string {
	if str, ok := sigName[sig]; ok {
		return str
	}
	return "unknown"
}

func (sig SignatureFlag) MarshalText() (text []byte, err error) {
	if str, ok := sigName[sig]; ok {
		return []byte(str), nil
	}
	return []byte("unknown"), nil
}

type Signature struct {
	Signature SignatureFlag
	Hash      []byte
}

// Get phar signature
//
// PHP Docs: https://www.php.net/manual/en/phar.fileformat.signature.php
//
// Important Golang not support have in std openssl module, and return [ErrOpenssl] if presence of openssl signature
func GetSignature(r io.ReaderAt, size int64) (*Signature, error) {
	bin := make([]byte, 8)
	_, err := r.ReadAt(bin, size-8)
	if err != nil {
		return nil, err
	}

	// Make new signature
	newSignature := &Signature{Signature: SignatureFlag(binary.LittleEndian.Uint32(bin[0:4]))}

	// GBMB string
	if binary.LittleEndian.Uint32(bin[4:]) != 1112359495 {
		return nil, ErrGBMB
	}

	var hashCalculator hash.Hash
	switch newSignature.Signature {
	case SignatureMD5:
		hashCalculator = md5.New()
		newSignature.Hash = make([]byte, 16)
		if _, err := r.ReadAt(newSignature.Hash, size-24); err != nil {
			return nil, fmt.Errorf("cannot get md5 hash: %s", err)
		}
	case SignatureSHA1:
		hashCalculator = sha1.New()
		newSignature.Hash = make([]byte, 20)
		if _, err := r.ReadAt(newSignature.Hash, size-28); err != nil {
			return nil, fmt.Errorf("cannot get sha1 hash: %s", err)
		}
	case SignatureSHA256:
		hashCalculator = sha256.New()
		newSignature.Hash = make([]byte, 32)
		if _, err := r.ReadAt(newSignature.Hash, size-40); err != nil {
			return nil, fmt.Errorf("cannot get sha256 hash: %s", err)
		}
	case SignatureSHA512:
		hashCalculator = sha512.New()
		newSignature.Hash = make([]byte, 64)
		if _, err := r.ReadAt(newSignature.Hash, size-72); err != nil {
			return nil, fmt.Errorf("cannot get sha512 hash: %s", err)
		}
	case SignatureOpenSSL, SignatureOpenSSLSha256, SignatureOpenSSLSha512:
		lenOffset := size - int64(pharSignatureStubLen) - int64(pharSignatureLenLen)
		if lenOffset < 0 {
			return nil, fmt.Errorf("negative offset")
		}
		lenBuf := make([]byte, pharSignatureLenLen)
		n, readErr := r.ReadAt(lenBuf, lenOffset)
		if readErr != nil {
			return nil, fmt.Errorf("reading signature length at offset %d: %v", lenOffset, readErr)
		} else if n != pharSignatureLenLen {
			return nil, fmt.Errorf("reading signature length at offset %d: expected %d bytes, got %d", lenOffset, pharSignatureLenLen, n)
		}

		sigLen32 := binary.LittleEndian.Uint32(lenBuf)
		if sigLen32 == 0 || sigLen32 > uint32(pharMaxSignatureLen) {
			return nil, fmt.Errorf("invalid signature length %d (must be > 0 and <= %d)", sigLen32, pharMaxSignatureLen)
		}
		sigLen := int64(sigLen32)
		sigOffset := size - int64(pharSignatureStubLen) - int64(pharSignatureLenLen) - sigLen
		if sigOffset < 0 {
			return nil, fmt.Errorf("calculated negative signature offset %d (size: %d, sigLen: %d)", sigOffset, size, sigLen)
		}

		newSignature.Hash = make([]byte, sigLen)
		n, readErr = r.ReadAt(newSignature.Hash, sigOffset)
		if readErr != nil && readErr != io.EOF {
			return nil, fmt.Errorf("reading signature data at offset %d (length %d): %v", sigOffset, sigLen, readErr)
		} else if int64(n) != sigLen {
			return nil, fmt.Errorf("reading signature data at offset %d: expected %d bytes, got %d", sigOffset, sigLen, n)
		}
		return newSignature, ErrOpenssl
	default:
		return nil, ErrInvalidSignature
	}

	// Check hash is same
	if _, err := io.CopyN(hashCalculator, newReaderFromReaderAt(r), size-int64(8+len(newSignature.Hash))); err != nil {
		return nil, err
	} else if !bytes.Equal(newSignature.Hash, hashCalculator.Sum(nil)) {
		return nil, ErrInvalidSignature
	}

	return newSignature, nil
}
