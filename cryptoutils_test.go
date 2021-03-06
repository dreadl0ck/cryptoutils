/*
 * CRYPTOUTILS - A thin wrapper for the x/crypto/nacl package and a few utils
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package cryptoutils

import "testing"

var (
	data                 = []byte("this is a test")
	pubKey1, privKey1, _ = GenerateKeypair()
)

/*
 *	Tests
 */

func TestSymmetricEncryption(t *testing.T) {

	key := GenerateKey("test")

	enc, err := SymmetricEncrypt(data, key)
	if err != nil {
		t.Fatal("failed to encrypt: ", err)
	}

	dec, err := SymmetricDecrypt(enc, key)
	if err != nil {
		t.Fatal("failed to decrypt: ", err)
	}

	if string(dec) != string(data) {
		t.Fatal("invalid result")
	}
}

func TestAsymmetricEncryption(t *testing.T) {

	// peer 1
	pubKey1, privKey1, err := GenerateKeypair()
	if err != nil {
		t.Fatal("failed to generate keypair: ", err)
	}

	// peer 2
	pubKey2, privKey2, err := GenerateKeypair()
	if err != nil {
		t.Fatal("failed to generate keypair: ", err)
	}

	enc, err := AsymmetricEncrypt(data, pubKey1, privKey2)
	if err != nil {
		t.Fatal("failed to encrypt: ", err)
	}

	dec, ok := AsymmetricDecrypt(enc, pubKey2, privKey1)
	if !ok {
		t.Fatal("failed to decrypt")
	}

	if string(dec) != string(data) {
		t.Fatal("invalid result")
	}
}

/*
 *	Benchmarks
 */

func BenchmarkSymmetricEncrypt(b *testing.B) {

	key := GenerateKey("test")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SymmetricEncrypt(data, key)
		if err != nil {
			b.Fatal("failed to encrypt: ", err)
		}
	}
}

func BenchmarkSymmetricDecrypt(b *testing.B) {

	key := GenerateKey("test")

	enc, err := SymmetricEncrypt(data, key)
	if err != nil {
		b.Fatal("failed to encrypt: ", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SymmetricDecrypt(enc, key)
		if err != nil {
			b.Fatal("failed to decrypt: ", err)
		}
	}
}

func BenchmarkAsymmetricEncrypt(b *testing.B) {

	// peer 1
	pubKey1, privKey1, err := GenerateKeypair()
	if err != nil {
		b.Fatal("failed to generate keypair: ", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := AsymmetricEncrypt(data, pubKey1, privKey1)
		if err != nil {
			b.Fatal("failed to encrypt: ", err)
		}
	}
}

func BenchmarkAsymmetricDecrypt(b *testing.B) {

	// peer 1
	pubKey1, privKey1, err := GenerateKeypair()
	if err != nil {
		b.Fatal("failed to generate keypair: ", err)
	}

	enc, err := AsymmetricEncrypt(data, pubKey1, privKey1)
	if err != nil {
		b.Fatal("failed to encrypt: ", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := AsymmetricDecrypt(enc, pubKey1, privKey1)
		if !ok {
			b.Fatal("failed to decrypt")
		}
	}
}
