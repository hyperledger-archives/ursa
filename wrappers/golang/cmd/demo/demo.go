package main

import (
	"fmt"
	"log"

	"github.com/mikaelaTar/ursa/wrappers/golang/crypto"
)

func main() {
	nonce, err := crypto.NewNonce()
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("Generated Nonce: ", nonce)
}
