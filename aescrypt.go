package aescrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	AESCryptVersion = 0x02
	KeySizeBytes    = 32
	IVSizeBytes     = 16
)

type AESCrypt struct {
	password   string
	derivedKey [KeySizeBytes]byte
	iv         []byte
}

func New(key string) *AESCrypt {
	return &AESCrypt{
		password:   key,
		derivedKey: sha256.Sum256([]byte(key)),
		iv:         nil,
	}
}

func (c *AESCrypt) Encrypt(fromPath, toPath string) error {

	plainFile, err := os.Open(fromPath)

	if err != nil {
		return fmt.Errorf("Unable to open the file to encrypt: %v", fromPath)
	}

	src, err := ioutil.ReadAll(plainFile)

	if err != nil {
		return fmt.Errorf("Unable to read the file to encrypt: %v", fromPath)
	}

	aesCipher, err := aes.NewCipher(c.derivedKey[:])

	if err != nil {
		return fmt.Errorf("Unable to istantiate AES cipher: %v", fromPath)
	}

	iv := c.getIV()

	cbcEncrypter := cipher.NewCBCEncrypter(aesCipher, iv)

	var dst *bytes.Buffer

	dst.Write([]byte("AES"))       //Byte representation of string 'AES'
	dst.WriteByte(AESCryptVersion) //Version
	dst.WriteByte(0x00)            //Reserverd
	dst.WriteByte(0x00)            //No extension
	dst.WriteByte(0x00)            //No extension

	dst.Write(iv)                                                 //16 bytes for Initialization Vector
	dst.Write(encryptIVAndKey(cbcEncrypter, iv, c.derivedKey[:])) // Encrypted IV + key

	fmt.Println(src)
	return nil
}

func (c *AESCrypt) Decrypt(fromPath, toPath string) error {
	return nil
}

func (c *AESCrypt) getIV() []byte {
	if c.iv == nil {
		c.iv = generateRandomIV()
	}
	return c.iv
}

func encryptIVAndKey(c cipher.BlockMode, iv []byte, key []byte) []byte {
	src := append(iv, key...)
	dst := make([]byte, KeySizeBytes+IVSizeBytes)
	c.CryptBlocks(dst, src)
	return dst
}

func generateHMAC(key []byte) []byte {
	return hmac.New(sha256.New, key).Sum()
}

func generateRandomIV() []byte {
	return make([]byte, IVSizeBytes)
}
