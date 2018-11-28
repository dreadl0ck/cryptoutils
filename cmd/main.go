package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/dreadl0ck/cryptoutils"
)

// flags
var (
	flagDir    = flag.String("d", "", "use directory")
	flagFile   = flag.String("f", "", "use file")
	flagString = flag.String("s", "", "use string")

	flagEncrypt = flag.Bool("enc", false, "encrypt file or directory")
	flagDecrypt = flag.Bool("dec", false, "decrypt file or directory")
	flagConvert = flag.String("c", "", "convert numeric values into their bin, dec, oct and hex representation")

	flagMD5    = flag.Bool("md5", false, "use md5")
	flagSha1   = flag.Bool("sha1", false, "use sha1")
	flagSha256 = flag.Bool("sha256", false, "use sha256")
	flagSha512 = flag.Bool("sha512", false, "use sha512")

	flagBase64 = flag.Bool("base64", false, "use base64")
)

// errors
var (
	// ErrUnkownCommand means we dont know what to do
	ErrUnkownCommand = errors.New("unkown command")
)

// usage:

// hashing:
// cryptotool -md5 -f <filename>
// cryptotool -md5 -d <dirname>
// cryptotool -md5 -s teststring
// echo "wtf" | cryptotool -md5
// ...

// crypto:
// cryptotool encrypt <filename>
// cryptotool encrypt <dirname>

// cryptotool decrypt <filename>
// cryptotool decrypt <dirname>

// read from stdin and decrypt to stdout
// cryptotool encrypt -

// cryptotool
func main() {

	flag.Parse()

	if len(os.Args) > 1 {

		switch true {
		case *flagMD5:
			hash(cryptoutils.MD5Data)
		case *flagSha1:
			hash(cryptoutils.Sha1Data)
		case *flagSha256:
			hash(cryptoutils.Sha256Data)
		case *flagSha512:
			hash(cryptoutils.Sha512Data)
		case *flagBase64:

			if isSet(*flagFile) {

				content, err := ioutil.ReadFile(*flagFile)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(base64.StdEncoding.EncodeToString(content))

			} else if isSet(*flagString) {
				fmt.Println(base64.StdEncoding.EncodeToString([]byte(*flagString)))
			} else {
				data, err := ioutil.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(base64.StdEncoding.EncodeToString(data))
			}

		case isSet(*flagConvert):
			bin, oct, dec, hex, err := cryptoutils.ConvertInt(*flagConvert)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("BIN:", bin)
			fmt.Println("OCT:", oct)
			fmt.Println("DEC:", dec)
			fmt.Println("HEX:", hex)
		case *flagEncrypt:

			info, err := os.Stat(*flagFile)
			if err != nil {
				log.Fatal(err)
			}
			if info.IsDir() {
				fmt.Println("its a dir")
				return
			}

			content, err := ioutil.ReadFile(*flagFile)
			if err != nil {
				log.Fatal(err)
			}

			enc, err := cryptoutils.SymmetricEncrypt(content, cryptoutils.GenerateKeyStdin())
			if err != nil {
				log.Fatal(err)
			}

			f, err := os.OpenFile(*flagFile+".enc", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()
			f.Write(enc)

			fmt.Println("created encrypted file: ", f.Name())

		case *flagDecrypt:

			info, err := os.Stat(*flagFile)
			if err != nil {
				log.Fatal(err)
			}
			if info.IsDir() {
				fmt.Println("its a dir")
				return
			}

			content, err := ioutil.ReadFile(*flagFile)
			if err != nil {
				log.Fatal(err)
			}

			dec, err := cryptoutils.SymmetricDecrypt(content, cryptoutils.ReadKeyStdin())
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(string(dec))
		default:
			log.Fatal(ErrUnkownCommand)
		}
	}
}

func hash(hashFunc cryptoutils.HashFunc) {
	if isSet(*flagFile) {

		hash, err := cryptoutils.HashFile(*flagFile, hashFunc)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)

	} else if isSet(*flagString) {
		fmt.Println(hex.EncodeToString(hashFunc([]byte(*flagString))))
	} else if isSet(*flagDir) {
		hash, err := cryptoutils.HashDir(*flagDir, hashFunc)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
	} else {
		data, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}

		// trim newline
		data = bytes.TrimSuffix(data, []byte{10})

		fmt.Println(hex.EncodeToString(hashFunc(data)))
	}
}

// check if flag is set or empty
func isSet(val string) bool {

	if val == "" {
		return false
	}
	return true
}
