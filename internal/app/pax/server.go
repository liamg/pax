package pax

import (
	"encoding/base64"
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
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, err := decrypt(encrypted, key); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

	}))
}
