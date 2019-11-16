package pax

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
)

func startVulnerableServer(key []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		keys, ok := r.URL.Query()["enc"]
		if !ok || len(keys) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		encrypted, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(keys[0], " ", "+"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if _, err := decrypt(encrypted, key); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

	}))
}
