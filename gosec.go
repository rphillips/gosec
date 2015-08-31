// Copyright 2015 Ryan Phillips. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"log"

	"github.com/bgentry/speakeasy"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var DefaultSecureRingPath = "~/.gnupg/secring.gpg"
var DefaultPublicRingPath = "~/.gnupg/pubring.gpg"
var DefaultPrompt = "password: "
var version = "No version provided"

func main() {
	directoryRootPtr := flag.String("s", "", "Directory")
	grepStringPtr := flag.String("g", "", "Regex String")
	decryptFlagPtr := flag.Bool("d", false, "Decrypt")
	encryptFlagPtr := flag.Bool("e", false, "Encrypt")
	versionFlagPtr := flag.Bool("v", false, "Display Version")
	flag.Parse()

	if *versionFlagPtr {
		Version()
		os.Exit(0)
	}

	if *directoryRootPtr == "" {
		Usage()
		fmt.Println("Root directory must be specified")
		os.Exit(1)
	}

	ctx := NewSecureContext(
		DefaultSecureRingPath,
		DefaultPublicRingPath,
		*directoryRootPtr,
	)

	err := ctx.ReadKeyRing()
	if err != nil {
		log.Fatal(err)
		return
	}

	_, err = ctx.GetPassword()
	if err != nil {
		log.Fatal(err)
		return
	}

	if *decryptFlagPtr == true {
		err = ctx.DecryptRoot()
		if err != nil {
			log.Fatal(err)
			return
		}
		return
	}

	if *encryptFlagPtr == true {
		err = ctx.EncryptRoot()
		if err != nil {
			log.Fatal(err)
			return
		}
		return
	}

	err = ctx.FindRegex(*grepStringPtr)
	if err != nil {
		log.Fatal(err)
		return
	}
}

type SecureContext struct {
	SecureRingPath string
	PubRingPath    string
	DirectoryRoot  string

	PrivateRing openpgp.EntityList
	PublicRing  openpgp.EntityList
	Password    string

	SearchRegex *regexp.Regexp
}

func NewSecureContext(secureRingPath, pubRingPath, directoryRoot string) *SecureContext {
	return &SecureContext{
		SecureRingPath: secureRingPath,
		PubRingPath:    pubRingPath,
		DirectoryRoot:  directoryRoot,
	}
}

func (ctx *SecureContext) GetPassword() (string, error) {
	var password string
	var err error
	if password, err = speakeasy.Ask(DefaultPrompt); err != nil {
		return "", err
	}
	ctx.Password = password
	return ctx.Password, nil
}

func (ctx *SecureContext) ReadKeyRing() error {
	secringPath, _ := expandPath(ctx.SecureRingPath)
	privringFile, err := os.Open(secringPath)
	if err != nil {
		return err
	}
	defer privringFile.Close()

	ctx.PrivateRing, err = openpgp.ReadKeyRing(privringFile)
	if err != nil {
		return err
	}

	pubringPath, _ := expandPath(ctx.PubRingPath)
	pubringFile, err := os.Open(pubringPath)
	if err != nil {
		return err
	}
	defer pubringFile.Close()

	ctx.PublicRing, err = openpgp.ReadKeyRing(pubringFile)
	return err
}

func (ctx *SecureContext) FindRegex(regexStr string) error {
	var regex *regexp.Regexp
	var err error

	if len(regexStr) > 0 {
		regex, err = regexp.Compile(regexStr)
		if err != nil {
			return err
		}
	}

	fileCallback := func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(fi.Name()) != ".gpg" {
			return nil
		}

		md, err := ctx.DecryptFile(path)
		if err != nil {
			return err
		}

		if regex != nil {
			newWriteLine := func(path string) func(uint64, string) {
				first := true
				return func(lineNumber uint64, line string) {
					if first {
						fmt.Println(path)
						first = false
					}
					fmt.Printf("%v:%v\n", lineNumber, line)
				}
			}

			foundMatch := false
			lineNumber := uint64(0)
			writeLine := newWriteLine(path)
			scanner := bufio.NewScanner(md.UnverifiedBody)
			for scanner.Scan() {
				lineNumber++
				line := scanner.Text()
				if regex.Match([]byte(line)) {
					foundMatch = true
					writeLine(lineNumber, line)
				}
			}

			if foundMatch {
				fmt.Println()
			}
		} else {
			io.Copy(os.Stdout, md.UnverifiedBody)
		}

		return nil
	}

	filesPath := path.Join(ctx.DirectoryRoot, "files")
	return filepath.Walk(filesPath, fileCallback)
}

func GetKeyByEmail(keyRing openpgp.EntityList, emailAddress string) *openpgp.Entity {
	for _, entity := range keyRing {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == emailAddress {
				if entity.PrimaryKey.PublicKey == nil {
					return nil
				}
				return entity
			}
		}
	}
	return nil
}

func (ctx *SecureContext) ReadAccessList() (openpgp.EntityList, error) {
	fp, err := os.Open(path.Join(ctx.DirectoryRoot, "access-list.conf"))
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	commentRegex, err := regexp.Compile("^#")
	if err != nil {
		return nil, err
	}

	entityList := openpgp.EntityList{}

	scanner := bufio.NewScanner(fp)
	for scanner.Scan() {
		line := scanner.Text()
		if commentRegex.Match([]byte(line)) {
			continue
		}
		entity := GetKeyByEmail(ctx.PublicRing, strings.TrimSpace(line))
		if entity == nil {
			return nil, errors.New(line + " not in keyring")
		}
		entityList = append(entityList, entity)
	}
	return entityList, nil
}

func (ctx *SecureContext) EncryptRoot() error {
	entityList, err := ctx.ReadAccessList()
	if err != nil {
		return err
	}

	fileCallback := func(filePath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(fi.Name()) != ".txt" {
			return nil
		}

		fp, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer fp.Close()

		filePath = strings.Replace(filePath, ".txt", ".gpg", 1)
		destRootPath := path.Join(ctx.DirectoryRoot, "files")
		destPath := path.Join(destRootPath, filepath.Base(filePath))

		_, err = os.Stat(destRootPath)
		if err != nil {
			err = os.Mkdir(destRootPath, 0700)
			if err != nil {
				return err
			}
		}

		destFp, err := os.Create(destPath)
		if err != nil {
			return err
		}
		defer destFp.Close()

		w, err := armor.Encode(destFp, "PGP MESSAGE", nil)
		if err != nil {
			return err
		}
		defer w.Close()

		cleartext, err := openpgp.Encrypt(w, entityList, nil, nil, nil)
		if err != nil {
			return err
		}
		io.Copy(cleartext, fp)
		cleartext.Close()

		return nil
	}

	return filepath.Walk(ctx.DirectoryRoot, fileCallback)
}

func (ctx *SecureContext) DecryptRoot() error {
	fileCallback := func(filePath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(fi.Name()) != ".gpg" {
			return nil
		}
		md, err := ctx.DecryptFile(filePath)
		if err != nil {
			return err
		}

		baseName := filepath.Base(filePath)
		newBase := strings.Replace(baseName, ".gpg", ".txt", 1)
		newFilePath := path.Join(ctx.DirectoryRoot, newBase)

		fp, err := os.Create(newFilePath)
		if err != nil {
			return err
		}
		defer fp.Close()
		_, err = io.Copy(fp, md.UnverifiedBody)
		return err
	}

	filesPath := path.Join(ctx.DirectoryRoot, "files")
	return filepath.Walk(filesPath, fileCallback)
}

func (ctx *SecureContext) DecryptFile(filePath string) (*openpgp.MessageDetails, error) {
	secfile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	block, err := armor.Decode(secfile)
	if err != nil {
		return nil, err
	}

	promptCallback := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		for _, k := range keys {
			err := k.PrivateKey.Decrypt([]byte(ctx.Password))
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
		return nil, errors.New("invalid password or no private key")
	}

	return openpgp.ReadMessage(block.Body, ctx.PrivateRing, promptCallback, nil)
}

func expandPath(p string) (string, error) {
	if path.IsAbs(p) {
		return p, nil
	}
	if p[:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		p = strings.Replace(p, "~", usr.HomeDir, 1)
	}
	return p, nil
}

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

var Version = func() {
	fmt.Fprintf(os.Stdout, "%s\n", version)
}
