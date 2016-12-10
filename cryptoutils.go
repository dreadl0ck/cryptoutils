/*
 *  cryptoutils
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package cryptoutils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	// ErrEncrypt means something went wrong encrypting
	// ErrEncrypt = errors.New("error encrypting")

	// ErrDecrypt means something went wrong decrypting
	ErrDecrypt = errors.New("error decrypting")
)

// KeySize is 256bit
const (
	KeySize   = 32
	NonceSize = 24
)

/*
 *	Nonce
 */

// GenerateNonce creates a new random nonce.
func GenerateNonce() (*[NonceSize]byte, error) {

	// alloc
	nonce := new([NonceSize]byte)

	// read from rand.Reader
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

/*
 *	Symmetric Encryption / Decryption
 */

// SymmetricEncryptStatic encrypts using a fixed nonce
func SymmetricEncryptStatic(data string, staticNonce *[NonceSize]byte, key *[KeySize]byte) []byte {

	// use the key as nonce
	out := make([]byte, NonceSize)

	copy(out, staticNonce[:])

	// encrypt with secretbox
	return secretbox.Seal(out, []byte(data), staticNonce, key)
}

// SymmetricEncrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
// A sealed message will the same size as the original message + secretbox.Overhead bytes long.
func SymmetricEncrypt(data []byte, key *[KeySize]byte) ([]byte, error) {

	// generate a new nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	out := make([]byte, NonceSize)
	copy(out, nonce[:])

	// encrypt with secretbox
	out = secretbox.Seal(out, data, nonce, key)
	return out, nil
}

// SymmetricDecrypt extracts the nonce from the ciphertext, and attempts to decrypt with NaCl's secretbox.
func SymmetricDecrypt(data []byte, key *[KeySize]byte) ([]byte, error) {

	// check if data is valid
	if len(data) < (NonceSize + secretbox.Overhead) {
		return nil, ErrDecrypt
	}

	// extract nonce
	var nonce [NonceSize]byte
	copy(nonce[:], data[:NonceSize])

	// decrypt with secretbox
	out, ok := secretbox.Open(nil, data[NonceSize:], &nonce, key)
	if !ok {
		return nil, ErrDecrypt
	}

	return out, nil
}

/*
 *	Asymmetric Encryption / Decryption
 */

// AsymmetricEncrypt encrypts a message for the given pubKey
func AsymmetricEncrypt(data []byte, pubKey, privKey *[KeySize]byte) ([]byte, error) {

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	// fmt.Println("nonce: ", hex.EncodeToString(nonce[:]))

	// init out and append nonce
	out := make([]byte, NonceSize)
	copy(out, nonce[:])

	return box.Seal(out, data, nonce, pubKey, privKey), nil
}

// AsymmetricDecrypt decrypts a message
func AsymmetricDecrypt(data []byte, pubKey, privKey *[KeySize]byte) ([]byte, bool) {

	// extract nonce
	var nonce [NonceSize]byte
	copy(nonce[:], data[:NonceSize])

	// fmt.Println("extracted nonce: ", hex.EncodeToString(nonce[:]))

	return box.Open(nil, data[NonceSize:], &nonce, pubKey, privKey)
}

/*
 *	Generate Encryption Keys
 */

// GenerateKeypair generates a public and a private key
func GenerateKeypair() (pubKey, privKey *[KeySize]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

// GenerateKey generates a Key, by calculating the SHA-256 Hash for the given string
func GenerateKey(data string) *[KeySize]byte {

	var (
		h256 = sha256.New()
		res  = new([KeySize]byte)
		hash []byte
	)

	io.WriteString(h256, data)
	hash = h256.Sum(nil)

	for i := 0; i < 32; i++ {
		res[i] = hash[i]
	}
	return res
}

/*
 *	Securely set the key by reading from stdin
 */

// GenerateKeyStdin can be used to set the encryption key by reading it from stdin
func GenerateKeyStdin() *[KeySize]byte {

	var key *[KeySize]byte

	for key == nil {
		password, err := PasswordPrompt("enter password: ")
		if err != nil {
			fmt.Println(err)
		} else {
			repeat, err := PasswordPrompt("repeat password: ")
			if err != nil {
				fmt.Println(err)
			} else {
				if repeat == password {
					key = GenerateKey(password)
				} else {
					fmt.Println("passwords don't match! please try again")
				}
			}
		}
	}

	return key
}

// PasswordPrompt reads a password from stdin without echoing the typed characters
func PasswordPrompt(prompt string) (password string, err error) {

	// create raw terminal and save state
	state, err := terminal.MakeRaw(0)
	if err != nil {
		log.Fatal(err)
	}

	// restore state when finished
	defer terminal.Restore(0, state)

	term := terminal.NewTerminal(os.Stdout, ">")

	// read pass
	password, err = term.ReadPassword(prompt)
	if err != nil {
		log.Fatal(err)
	}

	return
}

/*
 *	Hashes
 */

// MD5 returns an md5 hash of the given string
func MD5(text string) string {

	// init md5 hasher
	hasher := md5.New()

	// write data into it
	hasher.Write([]byte(text))

	// return as string
	return hex.EncodeToString(hasher.Sum(nil))
}

// Sha256 generates a Sha256 for the given data
func Sha256(data string) []byte {

	// init sha256 hasher
	h256 := sha256.New()

	// write data into it
	io.WriteString(h256, data)

	// return as []byte
	return h256.Sum(nil)
}

/*
 *	Random
 */

// RandomString generates a 32byte random string
func RandomString() (string, error) {

	// init byteslice
	rb := make([]byte, 32)

	// read from /dev/rand
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}

	// return as string
	return base64.URLEncoding.EncodeToString(rb), nil
}
