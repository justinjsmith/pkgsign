package main

import (
	"testing"
)

const (
	privKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAzSf+c1aQq6bgLv8YBbEQOL7+KJQMVJBUMdHoZeI6U+K89N7r
ac3Izt6GiTJjp/9A+y5OQtN+2P6aPH50icFayL+WRIyU3mMFKfTgIr9HPFn4gr3M
gZCS6gAs2OuatRB7NMRSmogDySCevQ81rrUheJFrSSELqhpvpSaW5PlrxmL7x6lb
lBlxOsfVGid0fsaYH5ouAt473XpLhKqOnD5VXlwG6VH2W33iSJcwnBBB7WNM+EMq
3cfvrxrbg5a40caQGxAS4jh5LuWNxSsqW1ns1aBmpj1N1T/nYwRyUbLV61NG5cSx
tJG9n2LhMRBQNUNxRenF4d3h0k5piY+M/AQS0QIDAQABAoIBAQDI67pPyx+0fKJi
ZIJqUJbKfIL9ysCosRFEGYe5AG6PaSgVyZxU6q0XrOelxivDhEFnvln3KJq6ed8k
D9SidTMsGDZavDOv+No91Q0N+rcRbCvuH2QCIE1Bzxoc9+F0IsgHTZ54qWzLtZ7B
GfxBNjOpmQGxhSOfXHSrEbgGWCAtEVMOoMXXbXIklGq8NTvE7ajtyIelXiD0aOoe
8VNsy+5QzUZFm8XjhaJM4btKd00NlFtCEeTmAgHaJe5+oZmrrdV0JOpfc/3d2e/N
DN3Md00cIzryr81Kvys5BWI8Lx/IhVwDFoNrUKkWEo3rFqWJfAIFq5K/hwVPabjF
049WJzABAoGBAOak+0QX0N2B6XoyQR3nq5j3TDZuJ6Tnn6hvaFeQaJumzio6sKrX
Cv7bbJWoDhfSdoFxDNBjXP/A4Kr7S9tXRoWm0mDv9FqX6XevSlfjzkLcgoOhBgNP
hToEIZg3+stu0Djchsy8NNPrhOM8bCIhynuehJ5qCKuBf1OXiVkZeeRhAoGBAOO1
srNbRvmxYDl2qE8E9byE7a2gPbIrAXmqq9qVZNp/9KRql+6SSG1bFxvQW0lClNIT
XWGgQ+n6o/aBRbHe6t18yHAqfra4lbvihOo7uqiWW/vinc/8BvpdUfm3HfCsi5aR
3OY1EW6rXXMZqypXn1TMMehnriMc9jyGOIiH3MRxAoGBAKXwRvLLq7LiV8dZxq2s
UzIfog57HDyxhJXbaZeuRwTNcwDA7wBK7RdFaQ8XNOSAwFAKtOxswKkk7L83Q3FQ
jmV0C2JA4W4YY5l/XR50wJ4sJh5ryHazTKfb9wucIu0gEeEHEFjWg6+AgEA45Zd8
9kAQYVvT797ssV3D5cZb5O2hAoGAVDR9x7uKTI2eQsGxTb9MzBDv/5PRHNCwc/h8
IpG6QN6ubhqI4o0vwVi8++kZyMaZV/IXRyHH2393IJH/Xt5LRep+CJR+VT1/CYKj
mibKSMuJamUL7LyLLAxUYx6nMLftyplX8b1QG/e8z/J/DGJopif4kLO+fneYSxtr
TnnHVtECgYEAmZ+OQ7yrJbrW1INy2GgtTj2/4gLs6jWOOyQtDeWEv1YafJ0rvI9Y
Z73WsopSttjZMZFFXrvbZ/YVAgu62+8QA8BCHZMNoOucy8uj5dgNeaOvsnt5ocyD
fNBu6VadvZjhYklrzbElb8l59mkruZj0ID0UKP91HhQQ0DLKGO55aRo=
-----END RSA PRIVATE KEY-----`

	privKeyWrongPEM = `-----BEGIN BAD DATA-----
MIIEpQIBAAKCAQEAzSf+c1aQq6bgLv8YBbEQOL7+KJQMVJBUMdHoZeI6U+K89N7r
ac3Izt6GiTJjp/9A+y5OQtN+2P6aPH50icFayL+WRIyU3mMFKfTgIr9HPFn4gr3M
gZCS6gAs2OuatRB7NMRSmogDySCevQ81rrUheJFrSSELqhpvpSaW5PlrxmL7x6lb
lBlxOsfVGid0fsaYH5ouAt473XpLhKqOnD5VXlwG6VH2W33iSJcwnBBB7WNM+EMq
3cfvrxrbg5a40caQGxAS4jh5LuWNxSsqW1ns1aBmpj1N1T/nYwRyUbLV61NG5cSx
tJG9n2LhMRBQNUNxRenF4d3h0k5piY+M/AQS0QIDAQABAoIBAQDI67pPyx+0fKJi
ZIJqUJbKfIL9ysCosRFEGYe5AG6PaSgVyZxU6q0XrOelxivDhEFnvln3KJq6ed8k
D9SidTMsGDZavDOv+No91Q0N+rcRbCvuH2QCIE1Bzxoc9+F0IsgHTZ54qWzLtZ7B
GfxBNjOpmQGxhSOfXHSrEbgGWCAtEVMOoMXXbXIklGq8NTvE7ajtyIelXiD0aOoe
8VNsy+5QzUZFm8XjhaJM4btKd00NlFtCEeTmAgHaJe5+oZmrrdV0JOpfc/3d2e/N
DN3Md00cIzryr81Kvys5BWI8Lx/IhVwDFoNrUKkWEo3rFqWJfAIFq5K/hwVPabjF
049WJzABAoGBAOak+0QX0N2B6XoyQR3nq5j3TDZuJ6Tnn6hvaFeQaJumzio6sKrX
Cv7bbJWoDhfSdoFxDNBjXP/A4Kr7S9tXRoWm0mDv9FqX6XevSlfjzkLcgoOhBgNP
hToEIZg3+stu0Djchsy8NNPrhOM8bCIhynuehJ5qCKuBf1OXiVkZeeRhAoGBAOO1
srNbRvmxYDl2qE8E9byE7a2gPbIrAXmqq9qVZNp/9KRql+6SSG1bFxvQW0lClNIT
XWGgQ+n6o/aBRbHe6t18yHAqfra4lbvihOo7uqiWW/vinc/8BvpdUfm3HfCsi5aR
3OY1EW6rXXMZqypXn1TMMehnriMc9jyGOIiH3MRxAoGBAKXwRvLLq7LiV8dZxq2s
UzIfog57HDyxhJXbaZeuRwTNcwDA7wBK7RdFaQ8XNOSAwFAKtOxswKkk7L83Q3FQ
jmV0C2JA4W4YY5l/XR50wJ4sJh5ryHazTKfb9wucIu0gEeEHEFjWg6+AgEA45Zd8
9kAQYVvT797ssV3D5cZb5O2hAoGAVDR9x7uKTI2eQsGxTb9MzBDv/5PRHNCwc/h8
IpG6QN6ubhqI4o0vwVi8++kZyMaZV/IXRyHH2393IJH/Xt5LRep+CJR+VT1/CYKj
mibKSMuJamUL7LyLLAxUYx6nMLftyplX8b1QG/e8z/J/DGJopif4kLO+fneYSxtr
TnnHVtECgYEAmZ+OQ7yrJbrW1INy2GgtTj2/4gLs6jWOOyQtDeWEv1YafJ0rvI9Y
Z73WsopSttjZMZFFXrvbZ/YVAgu62+8QA8BCHZMNoOucy8uj5dgNeaOvsnt5ocyD
fNBu6VadvZjhYklrzbElb8l59mkruZj0ID0UKP91HhQQ0DLKGO55aRo=
-----END RSA PRIVATE KEY-----`

	privKeyPEMEncrypted = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,bb68c308f8db9ded

jMvlUNp/Xdvm36BNtSpvQBexxoqq66jv0KD44NkXpVqXe8rVhlTJzXrfffTZm+nR
ixyoom6Mq4CpMyJk0ZMtdtYpRsa1pcRoEXVSn8mS522uys3oK9V3FgGakS9EYxaX
AUTPUfL3kox0dm8qVBZ+fc9vxdZd5/j9ZN7nIjOh7Swul/jRKARVWIcdazkPo/AN
0D2FqOcidV473tInj/LGDPv2tH1Yzp68HlbKNuB8r2S4qLOUmk3FulkVCG7VZAIE
gO3At33Rlp8l9p/VuPkZ8Xkoond++9yHQMVx3WIG9cTTDajLeEEDJs+nAGJ1Ku/A
ugI73UhOi9r1Ct6IncsYKKFJHhlK9L2pwT7GJP0KszRqvag274Cdo31AoYfUGzJM
egr2zFjoe6zIYvKy7HeZXbvQnhudR4N8nE/RhqSwWDjfSgIjHnj5pE+b98qOF8c/
kgFNNwOdSxceMMNHe0GhPdGhgbh8LZ87/6JtW4nXXGMi3agJoOmsIz2/m9CMAw51
jJgw+2Leg3b/90KaB/kgb3VHHkcKOQYz9Bsnq/Z9Bbx0hD1srP0ZVJjicC2MlGw0
on96EX3tM7YRJJytoFjYR3iPbqdDJWw9esHRxEPZWMJFDkfX53n9TNbYeP3kI1qT
uw15lviDmo8mARIw3BwsHT++42gX1cczlsyx0SffQ2+N76NKSxJ2Guv2p8Nr53YT
zeIyzXBGogb9Ky2YDPrz7qkRagZUjhBlpRHcMSJH2Q2bBNKCN1lWZ12bovoE4Pl9
cDGHRLUSPZ21M+9M4LWGm3aWWgms34H7TfreMF9Z9B5XUqvdoju+0YgQ2UrjZNXo
qXe8AqZHeN1pH/72p/ykz4AfacjINC+toP0YAEfI7TT7YFruxltrIeK2uibMiPa1
47ei9iuBwxbqwikExJ1J2IdGlSxjbfY9KvvS2g1EJoM0qVxmSO4rF5kErBRLfo9H
JrKcsOXt1nHmEjPVvgeivFSwotAj8qk2DDj4v03pH0tHOyNht68EQUO17QFeuHJA
P10oceZp7iIG/zOm25XUWbHCZ/tm9/6O2UHMiNbQOk8Czj7cIyzoPu4EXuquvZTq
w78w5tvDvvWbXIZLjDuK1RXDEqqbZkVcvzUajU7w/bl4fGBrvA0IYQ9mlp3j/7jb
7/ZIWfakJO62Cuq4QZ3H1ohFgpbH9iE5vTMOSqYY3DRAqtRPGx2CKeABYoXsgGtD
y1XjwZtkKddEmxdVa3hvXvN7rmQL1de6ZonZTZz2T7OGgRNPy+wUYYJqSqDGXPoG
Qlmg8LAuWj1qtMzmwmQyhaQPirByXIWbR4Vcbl8wkwJVCZKFOSPB49YX6FqSKsXi
6uhQX5EF9sQzjtSg+X2ZCReuydkJbssKg6F0ODV1bxs/7lR2K2QyC661vJvLVE7d
v/Zza/lqliVhyEHkVeRgJN/WCj6jBY39gwB9C61pMNz+mwMx7ET9RErCPqfgpWbO
f/rbnBaKCET70f0u/AfV3JYrjQzw7Q1AEso97/t4/39XBS+ck+yCmMsNqHx4tgOh
19DFgU0JcaS/JWsrUWQIf93GbDXkyDRPdr5SQ0kRDrJZE2AjZWyCjg==
-----END RSA PRIVATE KEY-----`

	privKeyPassphrase = `password`
)

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
