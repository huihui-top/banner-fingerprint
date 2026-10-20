package main

import (
	"os"

	"github.com/huihui-top/banner-fingerprint/internal/client"
)

func main() { os.Exit(client.Run(os.Args[1:], os.Stdout, os.Stderr)) }
