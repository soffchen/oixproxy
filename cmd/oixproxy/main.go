package main

import (
	"log"
	"os"

	"github.com/soffchen/oixproxy/internal/run"
)

func main() {
	if err := run.Main(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
