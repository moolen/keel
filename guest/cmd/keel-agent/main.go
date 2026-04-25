package main

import (
	"log"

	"github.com/moolen/keel/guest/internal/agent"
)

func main() {
	if err := agent.Run(); err != nil {
		log.Fatal(err)
	}
}
