package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

type shaTest struct {
	fileData string
	shaValue string
}

func newFile(testName string, data string, t *testing.T) (f *os.File) {
	dir := os.TempDir()
	f, err := ioutil.TempFile(dir, "_PkgSign_"+testName)
	if err != nil {
		t.Fatalf("TempFile %s: %s", testName, err)
	}
	f.WriteString(data)
	f.Seek(0, 0)
	if err != nil {
		t.Fatalf("TempFile write failed: %s", err)
	}
	return
}

func TestLoadKeyNoEncryption(t *testing.T) {
	key, err := loadKey([]byte(privKeyPem), []byte(""))
	if err != nil || key == nil {
		t.Fatal("Failed to load private key")
	}
	err = key.Validate()
	if err != nil {
		t.Fatal("Could not validate private key")
	}
}

func TestLoadKeyBadPassphrase(t *testing.T) {
	_, err := loadKey([]byte(privKeyPEMEncrypted), []byte("foo"))
	if err == nil {
		t.Fatal("Bad passphrase worked")
	}
}

func TestLoadEncryptedKey(t *testing.T) {
	key, err := loadKey([]byte(privKeyPem), []byte(privKeyPassphrase))
	if err != nil || key == nil {
		t.Fatal("Failed to load private key")
	}
	err = key.Validate()
	if err != nil {
		t.Fatal("Could not validate private key")
	}
}

func TestLoadBadKey(t *testing.T) {
	_, err := loadKey([]byte(privKeyWrongPEM), []byte(""))
	if err == nil {
		t.Fatal("Loaded bad key")
	}
}

func TestShas(t *testing.T) {
	tests := []shaTest{
		{smallChunk, `ebf81ddcbe5bf13aaabdc4d65354fdf2044f38a7`},
		{oneChunk, `23a8e5f23c5ab5f0e3c601d6e82253ef56c2a3dd`},
		{twoChunks, `9f88744c466b9dadf30cfdd045884bd5a78e6643`},
	}

	for _, st := range tests {
		file := newFile(st.shaValue, st.fileData, t)
		defer os.Remove(file.Name())

		sha := calcSha(file)
		shaStr := fmt.Sprintf("%x", sha)
		if shaStr != st.shaValue {
			t.Fatalf("Sha calculation failed: %s, got %s", st.shaValue, shaStr)
		}
	}
}
