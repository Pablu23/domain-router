package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

func main() {
	domains := make(map[string]int)
	domains["test.localhost"] = 8181
	domains["test2.localhost"] = 8282

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		port := domains[r.Host]
		fmt.Printf("Received request on Port: %d\n", port)
		// logRequest(*r)

		subUrlPath := r.URL.RequestURI()
		req, err := http.NewRequest(r.Method, fmt.Sprintf("http://localhost:%d%s", port, subUrlPath), r.Body)
		if err != nil {
			panic(err)
		}
		// logRequest(*req)
		for _, cookie := range r.Cookies() {
			fmt.Printf("Setting cookie, Name: %s, Value: %s\n", cookie.Name, cookie.Value)
			req.AddCookie(cookie)
		}

		// fmt.Println("Sending request to nested server")
		res, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		if loc, err := res.Location(); !errors.Is(err, http.ErrNoLocation) {
			http.Redirect(w, r, loc.RequestURI(), http.StatusFound)
			return
		}

		for _, cookie := range res.Cookies() {
			fmt.Printf("Setting cookie, Name: %s, Value: %s\n", cookie.Name, cookie.Value)
			http.SetCookie(w, cookie)
		}

		for name, values := range res.Header {
			for _, value := range values {
				// fmt.Printf("Adding Header vor name: %s, value: %s\n", name, value)
				w.Header().Set(name, value)
			}
		}
		w.WriteHeader(res.StatusCode)

		// fmt.Println("Reading Body")
		body, err := io.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}
		defer res.Body.Close()
		// fmt.Printf("Body: %s\n", hex.EncodeToString(body))

		_, err = w.Write(body)
		if err != nil {
			panic(err)
		}
		fmt.Println("----------------------------------------")
	})

	fmt.Println("Starting server on :80")
	http.ListenAndServe(":80", nil)
}

func logRequest(r http.Request) {
	fmt.Printf("URL: %s %s\n", r.Method, r.URL)
	fmt.Println("HEADER: ")
	for name, values := range r.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", name, value)
			// w.Header().Set(name, value)
		}
	}
	rbody, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("BODY: %s\n", rbody)
}
