# Phargo

Reader Php Phar files in golang

## Info

Parser supports several signature algorithms:
* md5
* sha1
* sha256
* sha512
* OpenSSL

Also supports compression formats:
* None
* Gzip
* Bzip2

Can read manifest version, alias and metadata. For every file inside PHAR-archive can read it contents, 
name, timestamp and metadata. Checks file CRC and signature of entire archive.

## Installation

1. Download and install:

```sh
go get -u github.com/Sirherobrine23/phargo
```

2. Import and use it:

```go
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/Sirherobrine23/phargo"
)

var pharFilePath = flag.String("file", "", "File path")

func main() {
	flag.Parse()

	// Open file
	file, err := os.Open(*pharFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open file: %s\n", err)
		os.Exit(1)
		return
	}

	// Get file size
	stat, _ := file.Stat()
	
	// Parse phar file
	pharInfo, err := phargo.NewReader(file, stat.Size())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse file: %s\n", err)
		os.Exit(1)
		return
	}

	// Encode in json output
	js := json.NewEncoder(os.Stdout)
	js.SetIndent("", "  ")
	js.Encode(pharInfo)
}
```

## Running the tests

Just run the command:

```sh
go test
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
