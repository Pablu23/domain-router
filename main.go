package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
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
		port, ok := domains[r.Host]
    if !ok {
      w.WriteHeader(http.StatusOK)
      return
    }

		rDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			panic(err)
		}

		subUrlPath := r.URL.RequestURI()
		req, err := http.NewRequest(r.Method, fmt.Sprintf("http://localhost:%d%s", port, subUrlPath), r.Body)
		if err != nil {
			panic(err)
		}

		for name, values := range r.Header {
			for _, value := range values {
				req.Header.Set(name, value)
			}
		}

		for _, cookie := range r.Cookies() {
			// fmt.Printf("Setting cookie, Name: %s, Value: %s\n", cookie.Name, cookie.Value)
			req.AddCookie(cookie)
		}

		reqDump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			panic(err)
		}

		res, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		cookies := res.Cookies()
		for _, cookie := range cookies {
			// fmt.Printf("Setting cookie, Name: %s, Value: %s\n", cookie.Name, cookie.Value)
			http.SetCookie(w, cookie)
		}

		resDump, err := httputil.DumpResponse(res, true)
		if err != nil {
			panic(err)
		}

		if loc, err := res.Location(); !errors.Is(err, http.ErrNoLocation) {
			http.Redirect(w, r, loc.RequestURI(), http.StatusFound)
		} else {
			for name, values := range res.Header {
				for _, value := range values {
					w.Header().Set(name, value)
				}
			}
			w.WriteHeader(res.StatusCode)

			body, err := io.ReadAll(res.Body)
			if err != nil {
				panic(err)
			}
			defer res.Body.Close()

			_, err = w.Write(body)
			if err != nil {
				panic(err)
			}

		}

		if r.Method == "POST" {
			fmt.Print(string(rDump) + "\n\n")
			fmt.Print(string(reqDump) + "\n\n")
			fmt.Print(string(resDump) + "\n")
			fmt.Println("----------------------------------------")
		}

	})

	fmt.Println("Starting server on :443")
	http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
}
