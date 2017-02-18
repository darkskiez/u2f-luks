package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/darkskiez/u2f-luks/u2fapp"
)

func main() {
	ctx := context.Background()
	app := u2fapp.NewClient("http://foobar.com")

	fmt.Println("Commands: (r)egister / (a)uthenticate")
	reader := bufio.NewReader(os.Stdin)

	khs := make([]u2fapp.KeyHandle, 0)

	for {
		char, _, err := reader.ReadRune()
		if err != nil {
			log.Fatal("Unable to read command stdin")
		}

		switch char {
		case 'r':
			fmt.Println("Touch or Insert Token to register")
			resp, err := app.Register(ctx)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				khs = append(khs, resp.KeyHandle)
				fmt.Printf("%+v\n", resp)
				fmt.Printf("Added Token %v\n", len(khs))
			}

		case 'a':
			fmt.Println("Touch or Insert Token to authenticate")
			aresp, err := app.Authenticate(ctx, khs)
			if err != nil {
				fmt.Printf("Err: %+v\n", err)
			} else {
				fmt.Printf("A: %+v\n", aresp)
			}
		}
	}
}
