package aescrypt

import (
	"crypto/sha256"
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	password := "thisisthepassword"
	aes := NewV2(password)

	require.Equal(t, AESCryptVersion2, aes.version)
	require.Equal(t, password, aes.password)
	require.Equal(t, sha256.Sum256([]byte(password)), aes.derivedKey)

	aes = NewV1(password)

	require.Equal(t, AESCryptVersion1, aes.version)
	require.Equal(t, password, aes.password)
	require.Equal(t, sha256.Sum256([]byte(password)), aes.derivedKey)
}

func TestThreeBytes(t *testing.T) {
	require.Equal(t, []byte{0x41, 0x45, 0x53}, []byte("AES"))
}

func TestRandomBytes(t *testing.T) {
	b := generateRandomBytesSlice(10)

	require.Equal(t, 10, len(b))

}

func TestIVKeyEncryption(t *testing.T) {
	encrypt(generateRandomAESKey(), generateRandomIV(), append(generateRandomIV(), generateRandomAESKey()...))
}

func TestEncrypt(t *testing.T) {

}

func TestDeepEqual(t *testing.T) {
	src := []byte("AESADC")

	require.False(t, reflect.DeepEqual(src, []byte("AES")))
	require.True(t, reflect.DeepEqual(src[:3], []byte("AES")))

	src = []byte("ADSADC")

	require.False(t, reflect.DeepEqual(src, []byte("AES")))
	require.False(t, reflect.DeepEqual(src[:3], []byte("AES")))
}

func TestExtensionBytesLengthConvert(t *testing.T) {
	require.EqualValues(t, 24, binary.BigEndian.Uint16([]byte{0x00, 0x18}))
}
