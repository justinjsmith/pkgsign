[![Build Status](https://travis-ci.org/justinjsmith/pkgsign.svg?branch=master)](https://travis-ci.org/justinjsmith/pkgsign)
# pkgsign
A simple utility for signing files with a private key. It is a companion to 
[pkgverify](http://github.com/justinjsmith/pkgverify). 

The goal of these two utilities is to add cryptographic assurance of file 
authorship and integrity.

````
pkgsign -file="/path/to/file/to/sign" -key="/path/to/key" -cert="/path/to/cert"
````

## Drop-dead simple way to create keys

In case you are in need of a simple way
to create PEM-encoded public/private key pairs, I recommend
[certstrap](http://github.com/square/certstrap). Instructions for creating a
certificate authority and creating signed certificates are  available on the
certstrap README.

## The basics
As an example, consider the `foo.tar.gz` file. If the `pkgsign` command is:

```
./pkgsign -file foo.tar.gz -key myCert.key -cert myCert.crt -corp SomeCorp -product SomeProduct
```

The result will be a JSON file that looks similar to the following:
```
{
	"Company": "SomeCorp",
	"Product": "SomeProduct",
    "PackageName": "foo.tar.gz",
    "PackageSha1": "aa0536a553ac680ad0458ae2414d6b1d2890c0b0",
    "ReleaseDate": "2015-07-09T11:06:11.268719779+08:00",
    "KeyId": 260771260056291337549802568420552178170,
    "Signature": "..."
}
```
This file is called the manifest and it will have the name 
`foo.tar.gz.manifest`.

The value of the `PackageSha1` field will be identical to the output of running
the `sha1sum` tool on the `foo.tar.gz` file.

The signature is calculated using the hash of the manifest without the 
signature field set. The signing algorithm is RSASSA-PKCS1-V1_5-SIGN from RSA 
PKCS#1 v1.5.

The KeyId is the serial number of the certificate that can be used to verify 
the signature. This is important in scenarios where an organization has 
multiple signing keys or rotates signing keys. Presumably such an organization 
would host all of it's certificates on a well-known URL, and this URL would be 
passed to the [pkgverify](http://github.com/justinjsmith/pkgverify) utility.

