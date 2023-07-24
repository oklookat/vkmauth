package main

import (
	"context"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/oklookat/vkmauth/vkm2fa"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	phone := os.Getenv("PHONE")
	password := os.Getenv("PASSWORD")

	// 2FA.
	ctx := context.Background()
	token, err := vkm2fa.New(ctx, phone, password, func(by vkm2fa.AuthSupportedWay) (string, error) {
		method := by.String()
		return readInput(method)
	})
	if err != nil {
		panic(err)
	}
	if len(token.AccessToken) == 0 {
		panic("Empty access token")
	}
	if len(token.RefreshToken) == 0 {
		panic("Empty refresh token")
	}

	println("All good.")
}

func readInput(method string) (string, error) {
	fmt.Printf("Code (from %s): ", method)
	var input string
	_, err := fmt.Scanln(&input)
	return input, err
}
