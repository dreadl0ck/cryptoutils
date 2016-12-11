package main

import (
	"c0de/cryptoutils"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// flags
var (
	flagDir    = flag.String("d", "", "use dir")
	flagFile   = flag.String("f", "", "use file")
	flagString = flag.String("s", "", "use string")

	flagMD5    = flag.Bool("md5", false, "use md5")
	flagSha1   = flag.Bool("sha1", false, "use sha1")
	flagSha256 = flag.Bool("sha256", false, "use sha256")
	flagSha512 = flag.Bool("sha512", false, "use sha512")

	flagBase64 = flag.Bool("base64", false, "use base64")
)

// errors
var (
// ErrCommandIncomplete = errors.New("command incomplete")
)

// usage:

// hashing:
// cryptotool -md5 -f <filename>
// cryptotool -md5 -s teststring
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

			if isSet(*flagFile) {

				hash, err := cryptoutils.HashFile(*flagFile, cryptoutils.MD5Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)

			} else if isSet(*flagString) {
				fmt.Println(hex.EncodeToString(cryptoutils.MD5Data([]byte(*flagString))))
			} else if isSet(*flagDir) {
				hash, err := cryptoutils.HashDir(*flagDir, cryptoutils.MD5Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)
			} else {
				data, err := ioutil.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(cryptoutils.MD5Data(data)))
			}

		case *flagSha1:

			if isSet(*flagFile) {

				hash, err := cryptoutils.HashFile(*flagFile, cryptoutils.Sha1Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)

			} else if isSet(*flagString) {
				fmt.Println(hex.EncodeToString(cryptoutils.Sha1Data([]byte(*flagString))))
			} else if isSet(*flagDir) {
				hash, err := cryptoutils.HashDir(*flagDir, cryptoutils.Sha1Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)
			} else {
				data, err := ioutil.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(cryptoutils.Sha1Data(data)))
			}

		case *flagSha256:

			if isSet(*flagFile) {

				hash, err := cryptoutils.HashFile(*flagFile, cryptoutils.Sha256Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)

			} else if isSet(*flagString) {
				fmt.Println(hex.EncodeToString(cryptoutils.Sha256Data([]byte(*flagString))))
			} else if isSet(*flagDir) {
				hash, err := cryptoutils.HashDir(*flagDir, cryptoutils.Sha256Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)
			} else {
				data, err := ioutil.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(cryptoutils.Sha256Data(data)))
			}

		case *flagSha512:

			if isSet(*flagFile) {

				hash, err := cryptoutils.HashFile(*flagFile, cryptoutils.Sha512Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)

			} else if isSet(*flagString) {
				fmt.Println(hex.EncodeToString(cryptoutils.Sha512Data([]byte(*flagString))))
			} else if isSet(*flagDir) {
				hash, err := cryptoutils.HashDir(*flagDir, cryptoutils.Sha512Data)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hash)
			} else {
				data, err := ioutil.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(hex.EncodeToString(cryptoutils.Sha512Data(data)))
			}

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

		case os.Args[1] == "convert":
			cryptoutils.ConvertInt(os.Args[2])
		case os.Args[1] == "encrypt":

			info, err := os.Stat(os.Args[2])
			if err != nil {
				log.Fatal(err)
			}
			if info.IsDir() {
				fmt.Println("its a dir")
				return
			}

			content, err := ioutil.ReadFile(os.Args[2])
			if err != nil {
				log.Fatal(err)
			}

			enc, err := cryptoutils.SymmetricEncrypt(content, cryptoutils.GenerateKeyStdin())
			if err != nil {
				log.Fatal(err)
			}

			f, err := os.OpenFile(os.Args[2]+".enc", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()
			f.Write(enc)

			fmt.Println("created encrypted file: ", f.Name())

		case os.Args[1] == "decrypt":

			info, err := os.Stat(os.Args[2])
			if err != nil {
				log.Fatal(err)
			}
			if info.IsDir() {
				fmt.Println("its a dir")
				return
			}

			content, err := ioutil.ReadFile(os.Args[2])
			if err != nil {
				log.Fatal(err)
			}

			dec, err := cryptoutils.SymmetricDecrypt(content, cryptoutils.GenerateKeyStdin())
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println(string(dec))

			// f, err := os.OpenFile(os.Args[2]+".enc", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0700)
			// if err != nil {
			// 	log.Fatal(err)
			// }

			// defer f.Close()
			// f.Write(enc)

			// fmt.Println("created encrypted file: ", f.Name())
		default:
			log.Fatal("unknown command")
		}
	}
}

// check if flag is set or empty
func isSet(val string) bool {

	if val == "" {
		return false
	}
	return true
}
