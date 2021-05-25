package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Hello", name)
}

func main() {
	log.Println("starting server")
	http.ListenAndServe(":3001", http.HandlerFunc(handler))
}
