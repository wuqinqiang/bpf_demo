package main

import (
	"fmt"
	"log"
	"net/http"
)

//go:noinline
func handlerFunc(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there from %s!", r.Host)
}

func main() {
	http.HandleFunc("/", handlerFunc)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
