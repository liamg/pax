package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/liamg/tml"

	"github.com/liamg/pax/internal/app/pax"

	"github.com/spf13/cobra"
)

var url string
var sample string
var cookies string
var blockSize int = 16
var method string = http.MethodGet

func init() {
	rootCmd.AddCommand(decryptCmd)
	rootCmd.PersistentFlags().StringVarP(&url, "url", "u", url, "The URL of the suspected padding oracle. Required.")
	rootCmd.PersistentFlags().StringVarP(&sample, "sample", "s", sample, "A sample of encrypted data, which can be base64 and/or url encoded. This sample should also appear at least one of the --url/--cookies. Required,")
	rootCmd.PersistentFlags().StringVarP(&cookies, "cookies", "c", cookies, "A string containing cookies. e.g. \"PHPSESSID=123456536;LOC=1;X=NO\".")
	rootCmd.PersistentFlags().IntVarP(&blockSize, "block-size", "b", blockSize, "The block size used by the padding oracle. Usually 8, 16, or 32.")
	rootCmd.PersistentFlags().StringVarP(&method, "method", "m", method, "The HTTP verb to use when sending requests to the oracle.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Short: "Exploit padding oracles for fun and profit",
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "attempt to decrypt data by exploiting a potential padding oracle",
	Run: func(cmd *cobra.Command, args []string) {

		if url == "" {
			tml.Printf("<red>You must supply a --url - run with the --help flag for details</red>\n")
			os.Exit(1)
		}

		if sample == "" {
			tml.Printf("<red>You must supply a --sample - run with the --help flag for details</red>\n")
			os.Exit(1)
		}

		options := pax.ExploitOptions{
			BlockSize: blockSize,
			Method:    method,
			Cookies:   cookies,
		}

		output, err := pax.Exploit(url, sample, &options)
		if err != nil {
			tml.Printf("<red>Exploit failed: %s</red>\n", err)
			os.Exit(1)
		}

		tml.Printf("<green>Decryption successful:</green>\n\n")

		tml.Printf("URL:        %s\n", url)
		tml.Printf("Input:      %s\n", sample)
		tml.Printf("Plaintext:\n\n%s\n\n", string(output))

	},
}
