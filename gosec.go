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

var secringPath = "~/.gnupg/secring.gpg"
var prompt = "password: "

func main() {
	var regex *regexp.Regexp
	var err error

	directoryRootPtr := flag.String("s", "", "Directory")
	grepStringPtr := flag.String("g", "", "Regex String")
	recipientEmailPtr := flag.String("r", "", "Recipient Email")
	flag.Parse()

	if *recipientEmailPtr == "" {
		Usage()
		fmt.Println("Recipient email must be specified")
		os.Exit(1)
	}

	if *directoryRootPtr == "" {
		Usage()
		fmt.Println("Root directory must be specified")
		os.Exit(1)
	}

	if *grepStringPtr != "" {
		regex, err = regexp.Compile(*grepStringPtr)
		if err != nil {
			log.Fatal(err)
		}
	}

	secringPath, _ = expandPath(secringPath)
	privringFile, err := os.Open(secringPath)
	if err != nil {
		log.Fatal(err)
		return
	}

	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		log.Fatal(err)
		return
	}

	password, err := gopass.GetPass(prompt)
	if err != nil {
		log.Fatal(err)
		return
	}

	fileCallback := func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if filepath.Ext(fi.Name()) == ".gpg" {
			return decryptFile(*recipientEmailPtr, password, path, regex, privring)
		}
		return nil
	}

	filesPath := path.Join(*directoryRootPtr, "files")
	err = filepath.Walk(filesPath, fileCallback)
	if err != nil {
		log.Fatal(err)
	}
}

func getKeyByEmail(keyring openpgp.EntityList, email string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.UserId.Email == email {
				return entity
			}
		}
	}
	return nil
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

func decryptFile(recipient, password, filePath string, regex *regexp.Regexp, privring openpgp.EntityList) error {
	secfile, err := os.Open(filePath)
	if err != nil {
		return err
	}

	block, err := armor.Decode(secfile)
	if err != nil {
		return err
	}

	recipientEntity := getKeyByEmail(privring, recipient)
	if recipientEntity == nil {
		return errors.New("Invalid Recipient")
	}

	ents := openpgp.EntityList([]*openpgp.Entity{recipientEntity})

	promptCallback := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		for _, k := range keys {
			err := k.PrivateKey.Decrypt([]byte(password))
			if err == nil {
				return nil, nil
			}
		}
		return nil, errors.New("invalid password or no private key")
	}

	md, err := openpgp.ReadMessage(block.Body, ents, promptCallback, nil)
	if err != nil {
		return err
	}

	if regex != nil {
		first := true
		lineNumber := 0
		foundMatch := false

		scanner := bufio.NewScanner(md.UnverifiedBody)
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			if regex.Match([]byte(line)) {
				foundMatch = true
				if first {
					fmt.Println(filePath)
					first = false
				}
				fmt.Printf("%v:%v\n", lineNumber, line)
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

var Usage = func() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}
