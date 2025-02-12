package main

import (
	"fmt"
	"os"

	"sirherobrine23.com.br/go-bds/go-proot"
	"sirherobrine23.com.br/go-bds/go-proot/filesystem"
)

func main() {
	caller := &proot.PRoot{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,

		Rootfs: filesystem.HostBind{
			Path:   "/",
			IsFile: false,
		},

		// Command test
		Command: os.Args[1:],
	}

	if err := caller.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err.Error())
		os.Exit(-1)
		return
	}

	err := caller.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err.Error())
		os.Exit(1)
		return
	}
}
