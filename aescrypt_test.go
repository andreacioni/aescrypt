package aescrypt

import (
	"crypto/hmac"
	"encoding/binary"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	password := "thisisthepassword"
	aes := NewV2(password)

	require.Equal(t, AESCryptVersion2, aes.version)
	require.Equal(t, []byte(password), aes.password)
	aes = NewV1(password)

	require.Equal(t, AESCryptVersion1, aes.version)
	require.Equal(t, []byte(password), aes.password)
}

func TestThreeBytes(t *testing.T) {
	require.Equal(t, []byte{0x41, 0x45, 0x53}, []byte("AES"))
}

func TestHMAC(t *testing.T) {
	k := generateRandomAESKey()
	b := generateRandomBytesSlice(10)

	require.True(t, hmac.Equal(evaluateHMAC(k, b), evaluateHMAC(k, b)))
}

func TestRandomBytes(t *testing.T) {
	b := generateRandomBytesSlice(10)

	require.Equal(t, 10, len(b))

}

func TestIVKeyEncryption(t *testing.T) {
	encrypt(generateRandomAESKey(), generateRandomIV(), append(generateRandomIV(), generateRandomAESKey()...), 0)
}

func TestEncryptV2(t *testing.T) {
	key := "password"

	err := NewV2(key).Encrypt("testdata/hello_world.txt", "testdata/txt.aes")

	require.NoError(t, err)

	err = NewV2(key).Decrypt("testdata/txt.aes", "testdata/hello_world.txt.1")

	require.NoError(t, err)

	err = os.Remove("testdata/txt.aes")

	require.NoError(t, err)

	err = os.Remove("testdata/hello_world.txt.1")

	require.NoError(t, err)
}

func TestEncryptV1(t *testing.T) {
	key := "password"

	err := NewV1(key).Encrypt("testdata/hello_world.txt", "testdata/txt.aes")

	require.NoError(t, err)

	err = NewV1(key).Decrypt("testdata/txt.aes", "testdata/hello_world.txt.1")

	require.NoError(t, err)

	err = os.Remove("testdata/txt.aes")

	require.NoError(t, err)

	err = os.Remove("testdata/hello_world.txt.1")

	require.NoError(t, err)
}

func TestEncryptNew(t *testing.T) {
	key := "password"

	err := New(key).Encrypt("testdata/hello_world.txt", "testdata/txt.aes")

	require.NoError(t, err)

	err = New(key).Decrypt("testdata/txt.aes", "testdata/hello_world.txt.1")

	require.NoError(t, err)

	err = os.Remove("testdata/txt.aes")

	require.NoError(t, err)

	err = os.Remove("testdata/hello_world.txt.1")

	require.NoError(t, err)
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

func TestPadding(t *testing.T) {
	text := []byte("Hello World!")
	padded := pkcs7Pad(text, BlockSizeBytes, len(text)%BlockSizeBytes)
	unpadded := pkcs7Unpad(padded, BlockSizeBytes, len(text)%BlockSizeBytes)

	require.EqualValues(t, 12, len(text))
	require.EqualValues(t, BlockSizeBytes, len(padded))

	require.Equal(t, append(text, []byte{0x04, 0x04, 0x04, 0x04}...), padded)

	require.Equal(t, text, unpadded)
}

func TestDecryptExternalFile(t *testing.T) {
	key := "password"

	err := New(key).Decrypt("testdata/hello_world_v2.txt.aes", "testdata/txt.aes")

	require.NoError(t, err)

	err = os.Remove("testdata/txt.aes")

	require.NoError(t, err)
}
