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
	SignatureMD5           SignatureFlag = 0x0001
	SignatureSHA1                        = 0x0002
	SignatureSHA256                      = 0x0003
	SignatureSHA512                      = 0x0004
	SignatureOPENSSL                     = 0x0010
	SignatureOPENSSLSHA256               = 0x0011
	SignatureOPENSSLSHA512               = 0x0012
)

var (
	ErrOpenssl          = errors.New("openssl is disabled in this implementation")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrGBMB             = errors.New("can't find GBMB constant at the end")

	sigName = map[SignatureFlag]string{
		SignatureMD5:           "MD5",
		SignatureSHA1:          "SHA1",
		SignatureSHA256:        "SHA256",
		SignatureSHA512:        "SHA512",
		SignatureOPENSSL:       "OPENSSL",
		SignatureOPENSSLSHA256: "OPENSSL_SHA256",
		SignatureOPENSSLSHA512: "OPENSSL_SHA512",
	}
)

type SignatureFlag uint32

func (sig SignatureFlag) String() string {
	if str, ok := sigName[sig]; ok {
		return str
	}
	return "unknown"
}

type Signature struct {
	Hash      []byte
	Signature SignatureFlag
	GBMB      uint32
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
	newSignature := &Signature{
		Signature: SignatureFlag(binary.LittleEndian.Uint32(bin[0:4])),
		GBMB:      binary.LittleEndian.Uint32(bin[4:]),
	}

	//GBMB string
	if newSignature.GBMB != 1112359495 {
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
	case SignatureOPENSSL, SignatureOPENSSLSHA256, SignatureOPENSSLSHA512:
		switch newSignature.Signature {
		case SignatureOPENSSL:
			if hashCalculator, err = openssl_sha1(); err != nil {
				return nil, err
			}
		case SignatureOPENSSLSHA256:
			if hashCalculator, err = openssl_sha256(); err != nil {
				return nil, err
			}
		case SignatureOPENSSLSHA512:
			if hashCalculator, err = openssl_sha512(); err != nil {
				return nil, err
			}
		}
		// Not implemented
		return nil, ErrOpenssl

		// {
		//   char sig_buf[8], *sig_ptr = sig_buf;
		//   zend_off_t read_len;
		// 			size_t end_of_phar;
		// 			if (-1 == php_stream_seek(fp, -8, SEEK_END) || (read_len = php_stream_tell(fp)) < 20 || 8 != php_stream_read(fp, sig_buf, 8) || memcmp(sig_buf+4, "GBMB", 4)) {
		// 				efree(savebuf);
		// 				php_stream_close(fp);
		// 				if (error) {
		// 					spprintf(error, 0, "phar \"%s\" has a broken signature", fname);
		// 				}
		// 				return FAILURE;
		// 			}
		// 			PHAR_GET_32(sig_ptr, sig_flags);
		// 			uint32_t signature_len;
		// 			char *sig;
		// 			zend_off_t whence;
		// 			/* we store the signature followed by the signature length */
		// 			if (-1 == php_stream_seek(fp, -12, SEEK_CUR) || 4 != php_stream_read(fp, sig_buf, 4)) {
		// 				efree(savebuf);
		// 				php_stream_close(fp);
		// 				if (error) {
		// 					spprintf(error, 0, "phar \"%s\" openssl signature length could not be read", fname);
		// 				}
		// 				return FAILURE;
		// 			}
		// 			sig_ptr = sig_buf;
		// 			PHAR_GET_32(sig_ptr, signature_len);
		// 			sig = (char *) emalloc(signature_len);
		// 			whence = signature_len + 4;
		// 			whence = -whence;
		// 			if (-1 == php_stream_seek(fp, whence, SEEK_CUR) || !(end_of_phar = php_stream_tell(fp)) || signature_len != php_stream_read(fp, sig, signature_len)) {
		// 				efree(savebuf);
		// 				efree(sig);
		// 				php_stream_close(fp);
		// 				if (error) {
		// 					spprintf(error, 0, "phar \"%s\" openssl signature could not be read", fname);
		// 				}
		// 				return FAILURE;
		// 			}
		// 			if (FAILURE == phar_verify_signature(fp, end_of_phar, sig_flags, sig, signature_len, fname, &signature, &sig_len, error)) {
		// 				efree(savebuf);
		// 				efree(sig);
		// 				php_stream_close(fp);
		// 				if (error) {
		// 					char *save = *error;
		// 					spprintf(error, 0, "phar \"%s\" openssl signature could not be verified: %s", fname, *error);
		// 					efree(save);
		// 				}
		// 				return FAILURE;
		// 			}
		// 			efree(sig);
		// }
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
