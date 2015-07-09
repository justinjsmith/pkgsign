# pkgsign
A simple utility for signing files with a private key. It is a companion to 
[pkgverify](http://github.com/justinjsmith/pkgverify). 

The goal of these two utilities is to add cryptographic assurance of file 
authorship and integrity.

````
pkgsign -f="/path/to/file/to/sign" -k="/path/to/key"
````

## Drop-dead simple way to create keys
In case you are in need of a simple way to create PEM-encoded public/private key
pairs, I recommend [certstrap](http://github.com/square/certstrap). Instructions
for creating a certificate authority and creating signed certificates are 
available on the certstrap README.

## The basics
As an example, consider the `foo.tar.gz` file. If the `pkgsign` command is:

```
./pkgsign -f foo.tar.gz -k myKey.key -c SomeCorp -p SomeProduct
```

The result will be a JSON file that looks similar to the following:
```
{
	"Company": "SomeCorp",
	"Product": "SomeProduct",
    "PackageName": "foo.tar.gz",
    "PackageSha1": "aa0536a553ac680ad0458ae2414d6b1d2890c0b0",
    "ReleaseDate": "2015-07-09T11:06:11.268719779+08:00",
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
