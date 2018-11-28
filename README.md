# CRYPTOUTILS

cryptoutils is a thin wrapper around the NaCl toolkit,
and offers hashing, integer conversion and securely reading passwords from stdin in the terminal.

The commandline tool is still work in progress.

## Library

Public Interface

```go
// Symmetric Crypto
func SymmetricDecrypt(data []byte, key *[KeySize]byte) ([]byte, error)
func SymmetricEncrypt(data []byte, key *[KeySize]byte) ([]byte, error)
func SymmetricEncryptStatic(data string, staticNonce *[NonceSize]byte, key *[KeySize]byte) []byte

// Asymmetric Crypto
func AsymmetricDecrypt(data []byte, pubKey, privKey *[KeySize]byte) ([]byte, bool)
func AsymmetricEncrypt(data []byte, pubKey, privKey *[KeySize]byte) ([]byte, error)

// Key & Nonce Generation
func GenerateKey(data string) *[KeySize]byte
func GenerateKeyStdin() *[KeySize]byte
func GenerateKeypair() (pubKey, privKey *[KeySize]byte, err error)
func GenerateNonce() (*[NonceSize]byte, error)

// Utils
func PasswordPrompt(prompt string) (password string, err error)

// Hashes
func MD5(text string) string
func RandomString() (string, error)
func Sha256(data string) []byte

```

### Library Examples

see the tests for sample usage

```go
// simple example for symmetric encryption
key := GenerateKey("test")

enc, err := SymmetricEncrypt(data, key)
if err != nil {
    log.Fatal("failed to encrypt: ", err)
}

dec, err := SymmetricDecrypt(enc, key)
if err != nil {
    log.Fatal("failed to decrypt: ", err)
}

// simple example for asymmetric encryption
// peer 1
pubKey1, privKey1, err := GenerateKeypair()
if err != nil {
    log.Fatal("failed to generate keypair: ", err)
}

// peer 2
pubKey2, privKey2, err := GenerateKeypair()
if err != nil {
    log.Fatal("failed to generate keypair: ", err)
}

enc, err := AsymmetricEncrypt(data, pubKey1, privKey2)
if err != nil {
    log.Fatal("failed to encrypt: ", err)
}

dec, ok := AsymmetricDecrypt(enc, pubKey2, privKey1)
if !ok {
    log.Fatal("failed to decrypt")
}
```

## Commandline Tool

The commandline tool provides all functionality of the library on the commandline.
It can also read input from stdin.

### Commandline Examples

By default output from cryptotool goes to stdout:

```shell
# encrypt input from stdin, user will be prompted to enter key
echo "test" | cryptotool -e

# encrypt input from stdin, with key "key"
echo "test" | cryptotool -e -k "key"

# encrypt file
cryptotool -e <filenam>

# decrypt file
cryptotool -d <filename>

# calculate the sha256 for "test"
cryptotool -sha256 "test"

# calculate the md5 for "test"
cryptotool -md5 "test"
```

## Benchmarks

Run the benchmarks and tests:

```shell
$ go test -v -bench=.
=== RUN   TestSymmetricEncryption
--- PASS: TestSymmetricEncryption (0.00s)
=== RUN   TestAsymmetricEncryption
--- PASS: TestAsymmetricEncryption (0.00s)
goos: darwin
goarch: amd64
pkg: github.com/dreadl0ck/cryptoutils
BenchmarkSymmetricEncrypt-12     	 2000000	       707 ns/op	     128 B/op	       3 allocs/op
BenchmarkSymmetricDecrypt-12     	 5000000	       279 ns/op	      16 B/op	       1 allocs/op
BenchmarkAsymmetricEncrypt-12    	   50000	     34467 ns/op	     128 B/op	       3 allocs/op
BenchmarkAsymmetricDecrypt-12    	   50000	     32642 ns/op	      16 B/op	       1 allocs/op
PASS
ok  	github.com/dreadl0ck/cryptoutils	7.907s
```

## Cryptographic Primitives

CRYPTOUTILS uses the famous NaCl Library from Daniel J. Bernstein.
more specifically the secretbox go implementation for symmetric encryption: [secretbox](https://github.com/golang/crypto/tree/master/nacl/secretbox) and the [box](https://github.com/golang/crypto/tree/master/nacl/box) implementation for asymmetric encryption.

Secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate messages with
secret-key cryptography. The length of messages is not hidden.

Box uses Curve25519, XSalsa20 and Poly1305 to encrypt and authenticate
messages. The length of messages is not hidden.

The KeySize is 256bit.
For every encryption procedure a fresh nonce is generated.

## LICENSE

GPLv3

## Contact

You have ideas, feedback, bugs, security issues, pull requests etc?
    Contact me: <dreadl0ck [at] protonmail [dot] ch>
