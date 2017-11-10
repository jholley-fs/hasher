package main

import (
	"crypto/md5"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Hasher - Holds search root and slice of file attributes
type Hasher struct {
	SearchDir string // root directory to be searched
	Files     []File // Files object holding all file information
	Exes      int    // count of EXE Files
	Dlls      int    // count of DLL files
}

// File - Holds file name, path, and hash attributes
type File struct {
	Name   string // file name
	Path   string // file path
	MD5    string // file MD5 hash
	SHA256 string // file SHA256 hash
}

// RecursiveHash - Recursively searches the SearchDir path for DLL and EXE files and calculates an MD5 hash for each
func (h *Hasher) RecursiveHash() (err error) {
	if h.SearchDir == "" {
		h.SearchDir = fmt.Sprintf("%s\\", os.Getenv("HOMEDRIVE"))
	}
	h.Exes = 0
	h.Dlls = 0
	//files := new(Files)

	fileList := []string{}
	currentDir := ""
	err = filepath.Walk(h.SearchDir, func(path string, f os.FileInfo, err error) error {
		if filepath.Ext(path) == ".exe" || filepath.Ext(path) == ".dll" {
			//fmt.Printf("Reading %s with file info %+v\n", path, f)
			fileList = append(fileList, path)
			if filepath.Ext(path) == ".exe" {
				h.Exes++
			} else if filepath.Ext(path) == ".dll" {
				h.Dlls++
			}
			if currentDir != filepath.Dir(path) {
				currentDir = filepath.Dir(path)
				//fmt.Printf("Processing %s\n", currentDir)
			}
			//fmt.Println(os.Stat(file))
			fileMd5 := getMd5(path)
			fileSha := getSha(path)

			fmt.Printf("Hash of %s MD5: %s SHA: %s\n\n", filepath.Base(path), fileMd5, fileSha)
			fileObj := new(File)
			fileObj.Name = filepath.Base(path)
			fileObj.Path = path
			fileObj.MD5 = fileMd5
			fileObj.SHA256 = fileSha
			h.Files = append(h.Files, *fileObj)
			// fmt.Printf("%+v\n", fileObj)
		} else {
			//fmt.Printf("File %s is not an exe or dll: %s\n", path, filepath.Ext(path))
		}
		return nil
	})

	if err != nil {
		fmt.Println("Walk error")
		msg := fmt.Sprintf("Unable to parse path: %s", h.SearchDir)
		err = errors.New(msg)
		return err
	}

	fmt.Printf("Total files: %d\nEXEs: %d\nDLLs: %d", len(h.Files), h.Exes, h.Dlls)
	return err
}

func getMd5(path string) (fileMd5 string) {
	f, _ := os.Open(path)
	md5 := md5.New()
	io.Copy(md5, f)
	fileMd5 = fmt.Sprintf("%x", md5.Sum(nil))
	f.Close()
	return fileMd5
}

func getSha(path string) (fileSha string) {
	f, _ := os.Open(path)
	sha := sha256.New()
	io.Copy(sha, f)
	fileSha = fmt.Sprintf("%x", sha.Sum(nil))
	f.Close()
	return fileSha
}

func main() {
	hasher := new(Hasher)
	err := hasher.RecursiveHash()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
