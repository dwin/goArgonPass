package main

import (
	"fmt"
	"os"

	"github.com/dwin/goArgonPass"
)

func main() {
	// Obtain user password from form or other input
	userPassInput := "password"
	// Custom Parameter configuration
	customParams := argonpass.ArgonParams{
		Time:        3,
		Memory:      512,
		Parallelism: 2,
		OutputSize:  16,
		Function:    argonpass.ArgonVariant2id, // can be `argon2i` or `argon2id`
	}

	// Hash with Default Parameters
	hash, err := argonpass.Hash(userPassInput)
	if err != nil {
		// Handle Error
		os.Exit(1)
	}
	fmt.Println("Hash Output: ", hash)
	// Verify Hash
	err = argonpass.Verify(userPassInput, hash)
	if err != nil {
		fmt.Println("Hash verification error: ", err)
	}
	fmt.Println("Hash verified")

	// Hash with Custom Parameters
	hash, err = argonpass.Hash(userPassInput, customParams)
	if err != nil {
		// Handle Error
		os.Exit(1)
	}
	fmt.Println("Hash Output: ", hash)
	// Verify Hash
	err = argonpass.Verify(userPassInput, hash)
	if err != nil {
		fmt.Println("Hash verification error: ", err)
	}
	fmt.Println("Hash verified")
}
