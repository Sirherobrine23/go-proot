package filesystem

import (
	"io/fs"
	"os"
	"path/filepath"
)

var _ Binding = (*HostBind)(nil)

// Implementes Binding to local files (same to mount --bind)
type HostBind struct {
	Path   string
	IsFile bool
}

// Bindings recomends to add to proot struct
var (
	Dev                  = HostBind{"/dev/", false}
	Sys                  = HostBind{"/sys/", false}
	Proc                 = HostBind{"/proc/", false}
	Tmp                  = HostBind{"/tmp/", false}
	Run                  = HostBind{"/run/", false}
	EtcetcNsswitchConfig = HostBind{"/etc/nsswitch.conf", true}
	EtcetcResolvConfig   = HostBind{"/etc/resolv.conf", true}
	EtcHostConfig        = HostBind{"/etc/host.conf", true}
	EtcHosts             = HostBind{"/etc/hosts", true}
	EtcHostsE            = HostBind{"/etc/hosts.equiv", true}
	EtcetcMtab           = HostBind{"/etc/mtab", true}
	EtcetcNetgroup       = HostBind{"/etc/netgroup", true}
	EtcetcNetworks       = HostBind{"/etc/networks", true}
	EtcetcPasswd         = HostBind{"/etc/passwd", true}
	EtcetcGroup          = HostBind{"/etc/group", true}
	EtcetcLocaltime      = HostBind{"/etc/localtime", true}

	// All recommended to add binding
	Recomends = []Binding{
		Dev,
		Sys,
		Proc,
		Tmp,
		Run,
		EtcetcNsswitchConfig,
		EtcetcResolvConfig,
		EtcHostConfig,
		EtcHosts,
		EtcHostsE,
		EtcetcMtab,
		EtcetcNetgroup,
		EtcetcNetworks,
		EtcetcPasswd,
		EtcetcGroup,
		EtcetcLocaltime,
	}
)

func (HostBind) ReadOnly() bool { return true }

func (local HostBind) OpenFile(name string, flags int, perm fs.FileMode) (File, error) {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.OpenFile(filepath.Join(local.Path, filepath.Clean(name)), flags, perm)
	}
	return os.OpenFile(local.Path, flags, perm)
}

func (local HostBind) Mkdir(name string, perm fs.FileMode) error {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.Mkdir(filepath.Join(local.Path, filepath.Clean(name)), perm)
	}
	return fs.ErrPermission
}

func (local HostBind) Symlink(oldname string, newname string) error {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.Symlink(filepath.Join(local.Path, filepath.Clean(oldname)), filepath.Join(local.Path, filepath.Clean(newname)))
	}
	return fs.ErrPermission
}

func (local HostBind) ReadDir(name string) ([]fs.DirEntry, error) {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.ReadDir(filepath.Join(local.Path, filepath.Clean(name)))
	}
	return nil, fs.ErrPermission
}

func (local HostBind) Stat(name string) (stat fs.FileInfo, err error) {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.Stat(filepath.Join(local.Path, filepath.Clean(name)))
	}
	return os.Stat(local.Path)
}

func (local HostBind) Chmod(name string, perm fs.FileMode) error {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.Chmod(filepath.Join(local.Path, filepath.Clean(name)), perm)
	}
	return os.Chmod(local.Path, perm)
}

func (local HostBind) Chown(name string, uid, gid int) error {
	if local.Path[len(local.Path)] == '/' || !local.IsFile {
		return os.Chown(filepath.Join(local.Path, filepath.Clean(name)), uid, gid)
	}
	return os.Chown(local.Path, uid, gid)
}
