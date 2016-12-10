package main

import (
	"c0de/cryptoutils"
	"fmt"
)

// cryptotool
func main() {

	key := cryptoutils.GenerateKeyStdin()

	fmt.Println("read key: ", key)
}
