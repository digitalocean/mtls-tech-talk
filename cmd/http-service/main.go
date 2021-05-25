package main

import (
	"fmt"
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
	http.ListenAndServe(":3001", http.HandlerFunc(handler))
}
