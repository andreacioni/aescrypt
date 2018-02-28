# aescrypt [![Travis CI](https://travis-ci.org/andreacioni/aescrypt.svg?branch=master)](https://travis-ci.org/andreacioni/aescrypt) [![Go Report Card](https://goreportcard.com/badge/github.com/andreacioni/aescrypt)](https://goreportcard.com/report/github.com/andreacioni/aescrypt) [![GoDoc](https://godoc.org/github.com/kubernetes/helm?status.svg)](https://godoc.org/github.com/andreacioni/aescrypt)
Golang implementation of AES file encryption/decryption compatible with [AES Crypt](https://www.aescrypt.com) version 1 & 2

**Example**

```go

aesCrypt := aescrypt.New("super_secret_password")

if err := aesCrypt.Encrypt("plain_text_file.txt", "plain_text_file.txt.aes"); err != nil {
    fmt.Print("Failed to encrypt the file: %v", err)
}

if err := aesCrypt.Decrypt("plain_text_file.txt.aes", "plain_text_file.txt"); err != nil {
    fmt.Print("Failed to decrypt the file: %v", err)
}

```

Made with <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/f/f1/Heart_coraz%C3%B3n.svg/220px-Heart_coraz%C3%B3n.svg.png" height="13
px"> by Andrea Cioni
