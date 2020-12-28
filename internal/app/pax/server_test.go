package pax

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

func startVulnerableServer(key []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var input string

		keys, ok := r.URL.Query()["enc"]
		if !ok || len(keys) != 1 {

			encCookie, err := r.Cookie("ENC")
			if err != nil || encCookie == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			input = encCookie.Value

		} else {
			input = keys[0]
		}

		encrypted, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(input, " ", "+"))
		if err != nil {
			fmt.Printf("Decoding of input (%s) failed: %s\n", input, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		data, err := decrypt(encrypted, key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

		_, _ = w.Write(data)
	}))
}
