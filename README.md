# Phargo

Reader Php Phar files in golang

## Info

Parser supports several signature algorithms:
* MD5
* SHA1
* SHA256
* SHA512
* ~~OPENSSL~~

Also supports compression formats:
* None
* GZ
* BZ2

Can read manifest version, alias and metadata. For every file inside PHAR-archive can read it contents, 
name, timestamp and metadata. Checks file CRC and signature of entire archive.

## Installation

1. Download and install:

```sh
go get -u github.com/Sirherobrine23/phargo
```

2. Import and use it:

In update 🚧

## Running the tests

Just run the command:

```sh
go test
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
