package aescrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
)

type AESVersion byte

const (
	AESCryptVersion1 AESVersion = 0x01
	AESCryptVersion2 AESVersion = 0x02
	BlockSizeBytes              = 32
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

func NewV1(key string) *AESCrypt {
	return New(AESCryptVersion1, key)
}

func NewV2(key string) *AESCrypt {
	return New(AESCryptVersion2, key)
}

func (c *AESCrypt) Encrypt(fromPath, toPath string) error {

	plainFile, err := os.Open(fromPath)

	if err != nil {
		return fmt.Errorf("unable to open the file to encrypt: %v", fromPath)
	}

	src, err := ioutil.ReadAll(plainFile)

	if err != nil {
		return fmt.Errorf("unable to read the file to encrypt: %v", fromPath)
	}

	iv1 := generateRandomIV()
	iv2 := generateRandomIV()
	aesKey1 := c.derivedKey[:]
	aesKey2 := generateRandomAESKey()

	var dst *bytes.Buffer

	dst.Write([]byte("AES"))       //Byte representation of string 'AES'
	dst.WriteByte(byte(c.version)) //Version
	dst.WriteByte(0x00)            //Reserverd

	if c.version == AESCryptVersion2 {
		dst.WriteByte(0x00) //No extension
		dst.WriteByte(0x00) //No extension
	}

	dst.Write(iv1)                                             //16 bytes for Initialization Vector
	ivKeyEnc := encrypt(aesKey1, iv1, append(iv2, aesKey2...)) // Encrypted IV + key
	dst.Write(ivKeyEnc)
	dst.Write(evaluateHMAC(aesKey1, ivKeyEnc)) // HMAC(Encrypted IV + key)

	lastBlockLength := byte((len(src) % BlockSizeBytes) & 0x0f)
	cipherData := encrypt(aesKey2, iv2, src)
	dst.Write(cipherData)
	dst.WriteByte(lastBlockLength)
	dst.Write(evaluateHMAC(aesKey2, cipherData))

	err = ioutil.WriteFile(toPath, dst.Bytes(), 0600)

	if err != nil {
		return fmt.Errorf("failed to write to destination file: %v", err)
	}
	return nil
}

func (c *AESCrypt) Decrypt(fromPath, toPath string) error {
	cipherFile, err := os.Open(fromPath)

	if err != nil {
		return fmt.Errorf("unable to open the file to decrypt: %v", fromPath)
	}

	src, err := ioutil.ReadAll(cipherFile)

	if err != nil {
		return fmt.Errorf("unable to read the file to decrypt: %v", fromPath)
	}

	if !reflect.DeepEqual(src[:3], []byte("AES")) {
		return fmt.Errorf("invalid file supplied. Are you sure it was encrypted with AESCrypt?")
	}

	switch src[3] {
	case byte(AESCryptVersion2):
		ivIndex, err := skipExtension(src)
		if err != nil {
			return fmt.Errorf("invalid extension found: %v", err)
		}
		src = src[ivIndex:]
		break
	case byte(AESCryptVersion1):
		src = src[5:]
		break
	default:
		return fmt.Errorf("version %d not supported", src[3])
	}

	if len(src) < IVSizeBytes {
		return fmt.Errorf("IV not found")
	}

	iv1 := src[:IVSizeBytes]
	aesKey1 := c.derivedKey[:]

	src = src[IVSizeBytes:] //Skip to encrypted IV+KEY

	if len(src) < IVSizeBytes+KeySizeBytes {
		return fmt.Errorf("encrypted IV+KEY not found")
	}

	ivKey := decrypt(aesKey1, iv1, src[:IVSizeBytes+KeySizeBytes])

	src = src[IVSizeBytes+KeySizeBytes:] //Skip to HMAC

	if len(src) < KeySizeBytes {
		return fmt.Errorf("first HMAC not found")
	}

	if !hmac.Equal(evaluateHMAC(aesKey1, ivKey), src[:KeySizeBytes]) {
		return fmt.Errorf("first HMAC doesn't match, entered password is not valid")
	}

	iv2 := ivKey[:IVSizeBytes]
	aesKey2 := ivKey[IVSizeBytes:]

	src = src[KeySizeBytes:]

	var dst *bytes.Buffer

	if len(src) < KeySizeBytes+1 { //HMAC + size byte
		return fmt.Errorf("no enough bytes for encrypted message")
	} else if len(src) > KeySizeBytes+1 { //Empty message not proceed inside this block
		cipherData := src[:len(src)-KeySizeBytes+1]
		dst.Write(decrypt(aesKey2, iv2, cipherData))

	}

	return nil
}

func (c *AESCrypt) getIV() []byte {
	if c.iv == nil {
		c.iv = generateRandomIV()
	}
	return c.iv
}

//skipExtension used to skip the extension part (if present).
//It returns the index of the first byte that contain IV
func skipExtension(src []byte) (int, error) {
	index := 7

	src = src[5:] //Skip reserved byte

	for {
		if len(src) < 2 {
			return 0, fmt.Errorf("extension length not available")
		}

		extLen := int(binary.BigEndian.Uint16(src[:2]))

		if extLen == 0 {
			return index, nil
		}

		src = src[2:] //Skip extension length

		if len(src) < int(extLen) {
			return 0, fmt.Errorf("size not match current extension length")
		}

		index += extLen
		src = src[index:]
	}
}

func decrypt(key, iv, src []byte) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	dst := make([]byte, len(src))

	cbc.CryptBlocks(dst, src)

	return dst
}

func encrypt(key, iv, src []byte) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	dst := make([]byte, len(src))

	cbc.CryptBlocks(dst, src)

	return dst
}

func evaluateHMAC(key, data []byte) []byte {
	return hmac.New(sha256.New, key).Sum(data)
}

func generateRandomAESKey() []byte {
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
