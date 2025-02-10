//go:build android || linux

package proot

import (
	"os"
	"path/filepath"
	"testing"

	"sirherobrine23.com.br/go-bds/go-proot/filesystem"
)

func TestInit(t *testing.T) {
	tmprdir := os.TempDir()
	caller := &PRoot{
		Rootfs: filesystem.HostBind{
			Path: filepath.Join(tmprdir, "rootfs"),
		},

		// Command test
		Command: []string{"bash", "-c", "go help; sleep 12s"},
	}

	if _, _, _, err := caller.AttachPipe(); err != nil {
		t.Error(err)
		return
	}

	if err := caller.Start(); err != nil {
		t.Error(err)
		return
	}

	caller.Process.Wait()
}
