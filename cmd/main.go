package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Sirherobrine23/phargo"
)

var (
	pharFilePath = flag.String("file", "", "File path")
	extractPath  = flag.String("extract", "", "Folder to extract files")
)

func main() {
	flag.Parse()

	file, err := os.Open(*pharFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot open file: %s\n", err)
		os.Exit(1)
		return
	}

	stat, _ := file.Stat()
	pharInfo, err := phargo.NewReader(file, stat.Size())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot parse file: %s\n", err)
		os.Exit(1)
		return
	}

	if *extractPath == "" {
		d, _ := json.MarshalIndent(pharInfo, "", "  ")
		fmt.Fprintf(os.Stdout, "%s\n", d)
		return
	}
	
	for _, file := range pharInfo.Files {
		pathSave := filepath.Join(*extractPath, file.Filename)
		f, err := file.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot extract %s file: %s\n", file.Filename, err)
			os.Exit(1)
			return
		}
		defer f.Close()
		
		if baseDir := filepath.Dir(pathSave); baseDir != "." {
			if _, err := os.Stat(baseDir); err != nil {
				os.MkdirAll(baseDir, 0755)
			}
		}
		
		w, err := os.Create(pathSave)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot create %s file: %s\n", pathSave, err)
			os.Exit(1)
			return
		}
		if _, err = io.Copy(w, f); err != nil {
			fmt.Fprintf(os.Stderr, "Cannot write to %s: %s\n", pathSave, err)
			os.Exit(1)
			return
		}
		f.Close()
		
		println(pathSave)
	}
}
