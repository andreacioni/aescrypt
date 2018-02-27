package aescrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
)

type AESVersion byte

const (
	AESCryptVersion1 AESVersion = 0x01
	AESCryptVersion2 AESVersion = 0x02
	KeySizeBytes                = 32
	IVSizeBytes                 = 16
)

type AESCrypt struct {
	version    AESVersion
	password   string
	derivedKey [KeySizeBytes]byte
	iv         []byte
}

func New(ver AESVersion, key string) *AESCrypt {
	return &AESCrypt{
		version:    ver,
		password:   key,
		derivedKey: sha256.Sum256([]byte(key)),
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

	iv1 := generateRandomIV()
	iv2 := generateRandomIV()

	var dst *bytes.Buffer

	dst.Write([]byte("AES"))       //Byte representation of string 'AES'
	dst.WriteByte(byte(c.version)) //Version
	dst.WriteByte(0x00)            //Reserverd

	if c.version == AESCryptVersion2 {
		dst.WriteByte(0x00) //No extension
		dst.WriteByte(0x00) //No extension
	}

	dst.Write(iv1)                                   //16 bytes for Initialization Vector
	ivKeyEnc := encryptIVAndKey(iv, c.derivedKey[:]) // Encrypted IV + key
	dst.Write(ivKeyEnc)
	dst.Write(evaluateHMAC(c.derivedKey[:], ivKeyEnc)) // HMAC(Encrypted IV + key)

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

func encryptIVAndKey(iv1, iv2, key1, key2 []byte) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCEncrypter(block, iv1)

	src := append(iv2, generateAESKey()...)
	dst := make([]byte, KeySizeBytes+IVSizeBytes)

	cbc.CryptBlocks(dst, src)

	return dst
}

func evaluateHMAC(key []byte, data []byte) []byte {
	return hmac.New(sha256.New, key).Sum(data)
}

func generateAESKey() []byte {
	return generateRandomBytesSlice(KeySizeBytes)
}

func generateRandomIV() []byte {
	return generateRandomBytesSlice(IVSizeBytes)
}

func generateRandomBytesSlice(size int) []byte {
	randSlice := make([]byte, size)
	_, err := rand.Read(randSlice)

	if err != nil {
		panic(err)
	}

	return randSlice
}
