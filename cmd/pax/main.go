package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "pax [url] [sample]",
	Short: "pax exploits a padding oracle to decrypt/encrypt data",
	Run: func(cmd *cobra.Command, args []string) {

		os.Exit(1)
	},
}
