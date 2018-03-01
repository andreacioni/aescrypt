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
	"unicode/utf16"
)

// AESVersion byte represents the version used by AESCrypt
type AESVersion byte

const (
	debug = false

	// AESCryptVersion1 -> version 1
	AESCryptVersion1 AESVersion = 0x01

	// AESCryptVersion2 -> version 2
	AESCryptVersion2 AESVersion = 0x02

	// BlockSizeBytes dimension (in bytes) of the block size
	BlockSizeBytes = 16

	//KeySizeBytes dimension (in bytes) of the key
	KeySizeBytes = 32

	// IVSizeBytes dimension (in bytes) of the IV
	IVSizeBytes = 16
)

// AESCrypt struct old some information about an instance of an encrypter/decrypter
type AESCrypt struct {
	version  AESVersion
	password []byte
}

// NewVersion build an AESCrypt instance with specified version and key.
// Specified version doesn't matter on decryption (version will be read from the supplied input file)
func NewVersion(ver AESVersion, key string) *AESCrypt {
	return &AESCrypt{
		version:  ver,
		password: toUtf16LE(key),
	}
}

// New build an AESCrypt instance using default version = 2 (shorthand for: NewV2(key))
func New(key string) *AESCrypt {
	return NewV2(key)
}

// NewV1 is a shorthand for NewVersion(AESCryptVersion1, key)
func NewV1(key string) *AESCrypt {
	return NewVersion(AESCryptVersion1, key)
}

// NewV2 is a shorthand for NewVersion(AESCryptVersion2, key)
func NewV2(key string) *AESCrypt {
	return NewVersion(AESCryptVersion2, key)
}

// Encrypt crypt the content of the file whose path is specified by 'fromPath'
// and save the result in the file whose path is specified by 'toPath'.
// If the output target file exist it will be overwritten
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
	aesKey1 := c.deriveKey(iv1)
	aesKey2 := generateRandomAESKey()

	debugf("IV 1: %x", iv1)
	debugf("IV 2: %x", iv2)
	debugf("AES 1: %x", aesKey1)
	debugf("AES 2: %x", aesKey2)

	var dst bytes.Buffer

	dst.Write([]byte("AES"))       //Byte representation of string 'AES'
	dst.WriteByte(byte(c.version)) //Version
	dst.WriteByte(0x00)            //Reserverd

	if c.version == AESCryptVersion2 {
		dst.WriteByte(0x00) //No extension
		dst.WriteByte(0x00) //No extension
	}

	dst.Write(iv1) //16 bytes for Initialization Vector
	ivKey := append(iv2, aesKey2...)
	ivKeyEnc := encrypt(aesKey1, iv1, ivKey, 0) // Encrypted IV + key

	debugf("IV+KEY: %x", ivKey)
	debugf("E(IV+KEY): %x", ivKeyEnc)

	dst.Write(ivKeyEnc)
	hmac1 := evaluateHMAC(aesKey1, ivKeyEnc)

	debugf("HMAC 1: %x", hmac1)

	dst.Write(hmac1) // HMAC(Encrypted IV + key)

	lastBlockLength := (len(src) % BlockSizeBytes)

	debugf("text: %x", src)

	cipherData := encrypt(aesKey2, iv2, src, lastBlockLength)

	debugf("E(text)+PAD: %x", cipherData)
	debugf("Last block size: %d", lastBlockLength)

	dst.Write(cipherData)
	dst.WriteByte(byte(lastBlockLength))

	hmac2 := evaluateHMAC(aesKey2, cipherData)

	debugf("HMAC 2: %x", hmac2)

	dst.Write(hmac2)

	err = ioutil.WriteFile(toPath, dst.Bytes(), 0600)

	if err != nil {
		return fmt.Errorf("failed to write to destination file: %v", err)
	}
	return nil
}

// Decrypt decrypt the content of the file whose path is specified by 'fromPath'
// and save the result in the file whose path is specified by 'toPath'.
// If the output target file exist it will be overwritten.
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
		if ivIndex > len(src) {
			return fmt.Errorf("no more bytes")
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
	aesKey1 := c.deriveKey(iv1)

	debugf("IV 1: %x", iv1)
	debugf("AES 1: %x", aesKey1)

	src = src[IVSizeBytes:] //Skip to encrypted IV+KEY

	if len(src) < IVSizeBytes+KeySizeBytes {
		return fmt.Errorf("encrypted IV+KEY not found")
	}

	ivKeyEnc := src[:IVSizeBytes+KeySizeBytes]
	ivKey := decrypt(aesKey1, iv1, ivKeyEnc, 0)

	debugf("E(IV+KEY): %x", ivKeyEnc)
	debugf("IV+KEY: %x", ivKey)

	iv2 := ivKey[:IVSizeBytes]
	aesKey2 := ivKey[IVSizeBytes:]

	debugf("IV 2: %x", iv2)
	debugf("AES 2: %x", aesKey2)

	src = src[IVSizeBytes+KeySizeBytes:] //Skip to HMAC

	if len(src) < KeySizeBytes {
		return fmt.Errorf("first HMAC not found")
	}
	hmac1 := src[:KeySizeBytes]
	debugf("HMAC 1: %x", hmac1)
	debugf("HMAC 1: %x", evaluateHMAC(aesKey1, ivKeyEnc))

	if !hmac.Equal(evaluateHMAC(aesKey1, ivKeyEnc), hmac1) {
		return fmt.Errorf("first HMAC doesn't match, entered password is not valid")
	}

	src = src[KeySizeBytes:] //Skip to encrypted message

	var dst bytes.Buffer

	if len(src) < KeySizeBytes+1 { //HMAC + size byte
		return fmt.Errorf("no enough bytes for encrypted message")
	} else if len(src) > KeySizeBytes+1 { //Empty message not proceed inside this block
		lastBlockLength := int(src[len(src)-KeySizeBytes-1])
		cipherData := src[:len(src)-KeySizeBytes-1]

		debugf("E(text)+PAD: %x", cipherData)
		debugf("Last block size: %d", lastBlockLength)

		hmac2 := evaluateHMAC(aesKey2, cipherData)

		debugf("HMAC 2: %x", hmac2)
		debugf("HMAC 2: %x", src[len(src)-KeySizeBytes:])

		cipherData = decrypt(aesKey2, iv2, cipherData, lastBlockLength)

		debugf("text: %x", cipherData)

		dst.Write(cipherData)

		if !hmac.Equal(hmac2, src[len(src)-KeySizeBytes:]) {
			return fmt.Errorf("second HMAC doesn't match, file is invalid")
		}

	}

	err = ioutil.WriteFile(toPath, dst.Bytes(), 0600)

	if err != nil {
		return fmt.Errorf("failed to write to destination file: %v", err)
	}
	return nil
}

func toUtf16LE(s string) []byte {
	encoded := utf16.Encode([]rune(s))

	b := make([]byte, 2*len(encoded))
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(b[index*2:], value)
	}

	return b
}

func (c *AESCrypt) deriveKey(iv []byte) []byte {
	aesKey := make([]byte, KeySizeBytes)
	copy(aesKey, iv)
	h := sha256.New()
	for i := 0; i < 8192; i++ {
		if _, err := h.Write(aesKey); err != nil {
			panic(err)
		}
		if _, err := h.Write(c.password); err != nil {
			panic(err)
		}
		aesKey = h.Sum(nil)
		h.Reset()
	}
	return aesKey
}

// skipExtension used to skip the extension part (if present).
// It returns the index of the first byte that contain IV
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

		index += extLen + 2
		src = src[extLen:]
	}
}

func decrypt(key, iv, src []byte, lastBlockSize int) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	dst := make([]byte, len(src))

	cbc.CryptBlocks(dst, src)

	dst = pkcs7Unpad(dst, BlockSizeBytes, lastBlockSize)

	return dst
}

func encrypt(key, iv, src []byte, lastBlockSize int) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	src = pkcs7Pad(src, BlockSizeBytes, lastBlockSize)

	dst := make([]byte, len(src))

	cbc.CryptBlocks(dst, src)

	return dst
}

func evaluateHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
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

func pkcs7Pad(b []byte, blocksize, lastBlockSize int) []byte {
	if lastBlockSize != 0 {
		toBeAdded := BlockSizeBytes - lastBlockSize
		a := make([]byte, toBeAdded)

		for i := range a {
			a[i] = byte(toBeAdded)
		}

		b = append(b, a...)

	}

	return b
}

func pkcs7Unpad(b []byte, blocksize, lastBlockSize int) []byte {
	if lastBlockSize != 0 {
		toBeRemoved := BlockSizeBytes - lastBlockSize

		b = b[:len(b)-toBeRemoved]
	}

	return b
}

func debugf(format string, a ...interface{}) {
	if debug {
		fmt.Printf(format, a)
		fmt.Println()
	}
}
