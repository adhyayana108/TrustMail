package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {

	port := ":8080"
	fmt.Printf("Server running on port %s\n", port)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}

}
