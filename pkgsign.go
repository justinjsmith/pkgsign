package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"go/scanner"
	"io"
	"io/ioutil"
	"math"
	"os"
	"time"

	"github.com/howeyc/gopass"
)

const filechunk = 8192

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
)

var (
	file     = flag.String("f", "file.tar.gz", "the file to sign")
	key      = flag.String("k", "key.pem", "the private key to use when signing")
	exitCode = 0
)

type Manifest struct {
	PackageName string
	PackageSha1 string
	ReleaseDate time.Time
	Signature   string
}

func usage() {
	fmt.Fprintf(os.Stderr, "\nusage: pkgsign -f [path] -k [path] -o [path]\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(2)
}

func report(err error) {
	scanner.PrintError(os.Stderr, err)
	exitCode = 2
}

func main() {
	pkgSignMain()
	os.Exit(exitCode)
}

func pkgSignMain() {
	flag.Usage = usage
	flag.Parse()

	fileToSign, err := os.Open(*file)
	if err != nil {
		report(err)
		return
	}
	defer fileToSign.Close()

	info, _ := fileToSign.Stat()
	filesize := info.Size()
	blocks := uint64(math.Ceil(float64(filesize) / float64(filechunk)))
	hash := sha1.New()
	for i := uint64(0); i < blocks; i++ {
		blocksize := int(math.Min(filechunk, float64(filesize-int64(i*filechunk))))
		buf := make([]byte, blocksize)
		fileToSign.Read(buf)
		io.WriteString(hash, string(buf))
	}
	sha1Hash := hash.Sum(nil)

	manifest := Manifest{
		PackageName: fileToSign.Name(),
		PackageSha1: fmt.Sprintf("%x", sha1Hash),
		ReleaseDate: time.Now(),
	}

	privKey, err := loadKey()
	if err != nil {
		report(err)
		return
	}
	var h crypto.Hash
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, h, sha1Hash)
	if err != nil {
		report(err)
		return
	}

	manifest.Signature = fmt.Sprintf("%x", sig)

	manBytes, err := json.Marshal(manifest)
	if err != nil {
		report(err)
		return
	}

	err = ioutil.WriteFile(fileToSign.Name()+".manifest", manBytes, 0777)
	if err != nil {
		report(err)
		return
	}

	fmt.Printf("Signed manifest written to %s\n", fileToSign.Name()+".manifest")
	return
}

func loadKey() (*rsa.PrivateKey, error) {
	keyBytes, err := ioutil.ReadFile(*key)
	if err != nil {
		return nil, err
	}
	passphrase := askPassPhrase()

	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, errors.New("cannot find the next PEM formatted block")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return parseKey(pemBlock, passphrase)
}

func parseKey(block *pem.Block, passphrase []byte) (*rsa.PrivateKey, error) {
	var blockBytes []byte
	if x509.IsEncryptedPEMBlock(block) {
		b, err := x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, err
		}
		blockBytes = b
	} else {
		blockBytes = block.Bytes
	}
	return x509.ParsePKCS1PrivateKey(blockBytes)
}

func askPassPhrase() []byte {
	fmt.Fprint(os.Stderr, "Enter passphrase (empty for no passphrase): ")
	pass := gopass.GetPasswd()
	fmt.Fprintln(os.Stderr)
	return pass
}
