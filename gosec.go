// Copyright 2014 Ryan Phillips. All Rights Reserved.
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

	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"code.google.com/p/gopass"
)

var DefaultSecureRingPath = "~/.gnupg/secring.gpg"
var DefaultPrompt = "password: "

func main() {
	directoryRootPtr := flag.String("s", "", "Directory")
	grepStringPtr := flag.String("g", "", "Regex String")
	flag.Parse()

	if *directoryRootPtr == "" {
		Usage()
		fmt.Println("Root directory must be specified")
		os.Exit(1)
	}

	ctx := NewSecureContext(
		DefaultSecureRingPath,
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

	err = ctx.FindRegex(*grepStringPtr)
	if err != nil {
		log.Fatal(err)
		return
	}
}

type SecureContext struct {
	SecureRingPath string
	DirectoryRoot  string

	PrivateRing openpgp.EntityList
	Password    string

	SearchRegex *regexp.Regexp
}

func NewSecureContext(secureRingPath, directoryRoot string) *SecureContext {
	return &SecureContext{
		SecureRingPath: secureRingPath,
		DirectoryRoot:  directoryRoot,
	}
}

func (ctx *SecureContext) GetPassword() (string, error) {
	var err error
	ctx.Password, err = gopass.GetPass(DefaultPrompt)
	if err != nil {
		log.Fatal(err)
		return "", err
	}
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

	return nil
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

		md, err := ctx.DecryptFile(path, regex)
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
	if err = filepath.Walk(filesPath, fileCallback); err != nil {
		return err
	}
	return nil
}

func (ctx *SecureContext) GetKeyByEmail(emailAddress string) *openpgp.Entity {
	for _, entity := range ctx.PrivateRing {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == emailAddress {
				return entity
			}
		}
	}
	return nil
}

func (ctx *SecureContext) DecryptFile(filePath string, regex *regexp.Regexp) (*openpgp.MessageDetails, error) {
	secfile, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer secfile.Close()

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
