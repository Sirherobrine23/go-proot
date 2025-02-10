// Implements basic system to emulate chroot in proot
package filesystem

import (
	"io"
	"io/fs"
	"os"
	"slices"
)

type File interface {
	Close() error
	Name() string
	Read(b []byte) (n int, err error)
	ReadAt(b []byte, off int64) (n int, err error)
	ReadDir(n int) ([]fs.DirEntry, error)
	ReadFrom(r io.Reader) (n int64, err error)
	Readdir(n int) ([]fs.FileInfo, error)
	Seek(offset int64, whence int) (ret int64, err error)
	Sync() error
	Write(b []byte) (n int, err error)
	WriteAt(b []byte, off int64) (n int, err error)
	WriteTo(w io.Writer) (n int64, err error)
}

type Binding interface {
	ReadOnly() bool
	OpenFile(name string, flags int, perm fs.FileMode) (File, error)
	Mkdir(name string, perm fs.FileMode) error
	Symlink(oldname string, newname string) error
	ReadDir(name string) ([]fs.DirEntry, error)
	Stat(name string) (stat fs.FileInfo, err error)
	Chmod(name string, perm fs.FileMode) error
	Chown(name string, uid, gid int) error
}

// Parse Flags from 'os.O_*'
type OsFlags int

func (f OsFlags) Flags() (flags []int) {
	if int(f)&os.O_RDONLY != 0 {
		flags = append(flags, os.O_RDONLY)
	}
	if int(f)&os.O_WRONLY != 0 {
		flags = append(flags, os.O_WRONLY)
	}
	if int(f)&os.O_RDWR != 0 {
		flags = append(flags, os.O_RDWR)
	}
	if int(f)&os.O_APPEND != 0 {
		flags = append(flags, os.O_APPEND)
	}
	if int(f)&os.O_CREATE != 0 {
		flags = append(flags, os.O_CREATE)
	}
	if int(f)&os.O_EXCL != 0 {
		flags = append(flags, os.O_EXCL)
	}
	if int(f)&os.O_SYNC != 0 {
		flags = append(flags, os.O_SYNC)
	}
	if int(f)&os.O_TRUNC != 0 {
		flags = append(flags, os.O_TRUNC)
	}
	return
}

// Check flag have write permissions
func (f OsFlags) IsRead() bool {
	flags := f.Flags()
	return slices.Contains(flags, os.O_RDWR) ||
		slices.Contains(flags, os.O_RDONLY)
}

// Check flag have write permissions
func (f OsFlags) IsWrite() bool {
	flags := f.Flags()
	return slices.Contains(flags, os.O_RDWR) ||
		slices.Contains(flags, os.O_WRONLY) ||
		slices.Contains(flags, os.O_CREATE) ||
		slices.Contains(flags, os.O_TRUNC)
}

func (f OsFlags) CreateIfNotExist() bool {
	flags := f.Flags()
	return slices.Contains(flags, os.O_CREATE)
}
