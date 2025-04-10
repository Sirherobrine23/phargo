//go:build cgo

package phargo

import (
	"hash"

	"github.com/golang-fips/openssl/v2"
)

func openssl_sha512() (hash.Hash, error) { return openssl.NewSHA512(), nil }
func openssl_sha256() (hash.Hash, error) { return openssl.NewSHA256(), nil }
func openssl_sha1() (hash.Hash, error)   { return openssl.NewSHA1(), nil }
