package main

import (
	"os"
	"pcg-master-thesis/ffarithmetics"
)

func main() {

	// go run main.go generate-fields
	if len(os.Args) > 1 && os.Args[1] == "generate-fields" {
		ffarithmetics.PreGenFieldArithmetics()
		return
	}

	// ... other commands:
}
