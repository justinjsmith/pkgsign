package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
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
	"math/big"
	"os"
	"time"

	"github.com/howeyc/gopass"
)

const filechunk = 8192

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
)

var (
	file        = flag.String("file", "", "the file to sign")
	packageName = flag.String("package", "", "the package name when used with the hash argument")
	key         = flag.String("key", "", "the private key to use when signing")
	hash        = flag.String("hash", "", "the checksum to sign")
	cert        = flag.String("cert", "", "the certificate")
	product     = flag.String("product", "", "the name of the product in the file (if applicable)")
	company     = flag.String("corp", "", "the name of the signing organization")
	exitCode    = 0
)

type Manifest struct {
	Company     string `json:",omitempty"`
	Product     string `json:",omitempty"`
	PackageName string
	PackageSha1 string // use string so value easy to compare with shasum output
	ReleaseDate time.Time
	KeyId       *big.Int
	Signature   []byte `json:",omitempty"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "\nusage: pkgsign -f [path] -k [path]\n")
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

	checkArgs()

	var pkgSha1 string
	var fileToSign *os.File
	if *file != "" {
		// open the file to sign and calculate the file's Sha1
		var err error
		fileToSign, err = os.Open(*file)
		if err != nil {
			report(err)
			return
		}
		defer fileToSign.Close()
		pkgSha1Bytes := calcSha(fileToSign)
		pkgSha1 = fmt.Sprintf("%x", pkgSha1Bytes)
	} else {
		// take the sha from the argument
		pkgSha1 = *hash
	}

	// verify the certificate and private key are related & get the cert serial
	// number
	serialNumber, err := loadCert(*cert, *key)
	if err != nil {
		report(err)
		return
	}

	var pkgName string
	if fileToSign == nil {
		pkgName = *packageName
	} else {
		pkgName = fileToSign.Name()
	}

	// build the manifest object
	manifest := Manifest{
		Company:     *company,
		Product:     *product,
		PackageName: pkgName,
		PackageSha1: pkgSha1,
		ReleaseDate: time.Now(),
		KeyId:       serialNumber,
	}

	// open the key, parse it and decrypt it (if needed)
	keyBytes, err := ioutil.ReadFile(*key)
	if err != nil {
		report(err)
		return
	}
	privKey, err := loadKey(keyBytes, askPassPhrase())
	if err != nil {
		report(err)
		return
	}

	// sign the manifest and write it to disk
	manBytes, err := signManifest(manifest, privKey)
	if err != nil {
		report(err)
		return
	}
	err = ioutil.WriteFile(pkgName+".manifest", manBytes, 0444)
	if err != nil {
		report(err)
		return
	}

	fmt.Printf("Signed manifest written to %s\n", pkgName+".manifest")
	return
}

func checkArgs() {
	if *key == "" || *cert == "" {
		usage()
	}

	if *hash == "" && *file == "" {
		usage()
	}

	if *hash != "" && *file != "" {
		usage()
	}

	if *hash != "" && *packageName == "" {
		usage()
	}

	if *file != "" && *packageName != "" {
		usage()
	}
}

func loadCert(cert, key string) (*big.Int, error) {
	tlsCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, err
	}
	return x509Cert.SerialNumber, nil
}

func signManifest(manifest Manifest, privKey *rsa.PrivateKey) ([]byte, error) {
	// marshal the manifest (without the signature field set)
	manifestToSign, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}

	// calculate the Sha1 of the manifest bytes
	var h crypto.Hash
	manifestSha1 := sha1.New()
	manifestSha1.Write(manifestToSign)
	manShaVal := manifestSha1.Sum(nil)

	// calculate the signature of the manifest
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, h, manShaVal)
	if err != nil {
		return nil, err
	}

	// set the Signature field of the manifest
	manifest.Signature = sig

	// marshal the manifest with signature
	return json.Marshal(manifest)
}

func calcSha(fileToSign *os.File) []byte {
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
	return hash.Sum(nil)
}

func loadKey(keyBytes, passphrase []byte) (*rsa.PrivateKey, error) {
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
