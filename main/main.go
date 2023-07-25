/** test */
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/oklookat/vkmauth"
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
	token, err := vkmauth.New(ctx, phone, password, onCodeWaiting)
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

func onCodeWaiting(by vkmauth.CodeSended) (vkmauth.GotCode, error) {
	got := vkmauth.GotCode{}
	// if len(by.Resend) > 0 && by.Current == vkmauth.AuthSupportedWayPush {
	// 	got.Resend = true
	// 	println("resend, next expected method: ", by.Resend.String())
	// 	return got, nil
	// }
	// if len(by.Resend) > 0 && by.Current == vkmauth.AuthSupportedWaySms {
	// 	got.Resend = true
	// 	println("resend, next expected method: ", by.Resend.String())
	// 	return got, nil
	// }
	code, err := readInput(by.Current.String())
	if err != nil {
		return got, err
	}
	got.Code = code
	return got, err
}

func readInput(method string) (string, error) {
	fmt.Printf("Code (from %s): ", method)
	var input string
	_, err := fmt.Scanln(&input)
	return input, err
}
