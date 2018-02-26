package aescrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	password := "thisisthepassword"
	aes := New(password)

	require.Equal(t, password, aes.password)
	require.Equal(t, sha256.Sum256([]byte(password)), aes.derivedKey)
}

func TestThreeBytes(t *testing.T) {
	require.Equal(t, []byte{0x41, 0x45, 0x53}, []byte("AES"))
}

func TestIVKeyEncryption(t *testing.T) {
	iv := []byte("ffffffffffffffff")                  //66 hex
	key := []byte("ffffffffffffffffaaaaaaaaaaaaaaaa") //66 hex + 61 hex

	require.Equal(t, 16, len(iv))
	require.Equal(t, 32, len(key))

	aesCipher, err := aes.NewCipher(key)

	require.NoError(t, err)

	cbcEncrypter := cipher.NewCBCEncrypter(aesCipher, iv)

	encryptIVAndKey(cbcEncrypter, iv, key)
}

func TestEncrypt(t *testing.T) {

}
