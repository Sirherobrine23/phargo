//go:build !cgo
package phargo

func openssl_sha512() (hash.Hash, error) { return nil, ErrOpenssl }
func openssl_sha256() (hash.Hash, error) { return nil, ErrOpenssl }
func openssl_sha1() (hash.Hash, error)   { return nil, ErrOpenssl }