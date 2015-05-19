## Gosec

[![Build Status](https://travis-ci.org/rphillips/gosec.svg?branch=master)](https://travis-ci.org/rphillips/gosec)

Gosec manages secrets using PGP. Given the following project layout it will
decrypt/encrypt/grep through given secrets:

```bash
project1/files/logins.gpg
project2/files/cloud.gpg
```

For example, to grep for `accountA` in `project1`:

```bash
gosec -s project1 -g accountA
```

## Usage

```bash
Usage of ./gosec:
-d=false: Decrypt
-e=false: Encrypt
-g="": Regex String
-s="": Directory
Root directory must be specified
```

## Install

```bash
go get https://github.com/rphillips/gosec
```
