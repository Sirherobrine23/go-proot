package main

import (
	"os"
	"path/filepath"

	"sirherobrine23.com.br/go-bds/go-proot"
	"sirherobrine23.com.br/go-bds/go-proot/filesystem"
)

func main() {
	tmprdir := os.TempDir()
	caller := &proot.PRoot{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,

		Rootfs: filesystem.HostBind{
			Path:   filepath.Join(tmprdir, "rootfs"),
			IsFile: false,
		},

		// Command test
		Command: []string{"env"},
	}

	if err := caller.Start(); err != nil {
		println(err.Error())
		os.Exit(-1)
		return
	}

	status, err := caller.Process.Wait()
	if err != nil {
		println(err.Error())
		os.Exit(-1)
		return
	}
	os.Exit(status.ExitCode())
}
