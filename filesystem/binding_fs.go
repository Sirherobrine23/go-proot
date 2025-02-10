package filesystem

import (
	"io"
	"io/fs"
	"path"
	"path/filepath"
)

var _ File = (*FSSFile)(nil)

type FSSFile struct {
	fs.File
	fileName string
	ressek   func() error // function to reopen file if not implements Seek function
}

func (fssFile FSSFile) Name() string { return path.Base(filepath.ToSlash(fssFile.fileName)) }
func (fssFile *FSSFile) WriteTo(w io.Writer) (n int64, err error) {
	if WW, ok := fssFile.File.(io.WriterTo); ok {
		return WW.WriteTo(w)
	}
	return io.Copy(w, fssFile.File)
}

func (fssFile *FSSFile) Write(b []byte) (n int, err error) {
	if w, ok := fssFile.File.(io.Writer); ok {
		return w.Write(b)
	}
	return 0, fs.ErrInvalid
}

func (fssFile *FSSFile) ReadFrom(r io.Reader) (n int64, err error) {
	if RR, ok := fssFile.File.(io.ReaderFrom); ok {
		return RR.ReadFrom(r)
	}
	return io.Copy(fssFile, r)
}

func (open FSSFile) Seek(offset int64, whence int) (ret int64, err error) {
	if s, ok := open.File.(io.Seeker); ok {
		return s.Seek(offset, whence)
	}
	info, _ := open.File.Stat()
	switch whence {
	case io.SeekStart:
		open.Close()
		if err = open.ressek(); err != nil {
			return 0, err
		}
		return io.CopyN(io.Discard, open, offset)
	case io.SeekCurrent:
		if _, err := io.CopyN(io.Discard, open, offset); err != nil {
			return 0, err
		}
	case io.SeekEnd:
		newOffset := info.Size() - offset
		if newOffset < 0 {
			return 0, io.EOF
		}
		open.Close()
		if err = open.ressek(); err != nil {
			return 0, err
		}
		return io.CopyN(io.Discard, open, newOffset)
	default:
		return 0, fs.ErrInvalid
	}

	return 0, nil
}

func (fssFile *FSSFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if v, ok := fssFile.File.(fs.ReadDirFile); ok {
		return v.ReadDir(n)
	}
	return nil, fs.ErrInvalid
}

func (fssFile *FSSFile) Readdir(n int) ([]fs.FileInfo, error) {
	if v, ok := fssFile.File.(interface {
		Readdir(n int) ([]fs.FileInfo, error)
	}); ok {
		return v.Readdir(n)
	}
	return nil, fs.ErrInvalid
}

func (fssFile *FSSFile) Sync() error {
	if v, ok := fssFile.File.(interface{ Sync() error }); ok {
		return v.Sync()
	}
	return nil
}

func (fssFile *FSSFile) ReadAt(b []byte, off int64) (n int, err error) {
	if v, ok := fssFile.File.(interface {
		ReadAt(b []byte, off int64) (n int, err error)
	}); ok {
		return v.ReadAt(b, off)
	}
	return 0, fs.ErrInvalid
}

func (fssFile *FSSFile) WriteAt(b []byte, off int64) (n int, err error) {
	if v, ok := fssFile.File.(interface {
		WriteAt(b []byte, off int64) (n int, err error)
	}); ok {
		return v.WriteAt(b, off)
	}
	return 0, fs.ErrInvalid
}

var _ Binding = (*FS)(nil)

// Implement Binding to [io/fs.FS]
type FS struct {
	fs.FS
}

func (FS) ReadOnly() bool                               { return true }
func (FS) Mkdir(name string, perm fs.FileMode) error    { return fs.ErrInvalid }
func (FS) Symlink(oldname string, newname string) error { return fs.ErrInvalid }
func (FS) Chmod(name string, perm fs.FileMode) error    { return fs.ErrInvalid }
func (FS) Chown(name string, uid, gid int) error        { return fs.ErrInvalid }

func (fss FS) ReadDir(name string) ([]fs.DirEntry, error)     { return fs.ReadDir(fss.FS, name) }
func (fss FS) Stat(name string) (stat fs.FileInfo, err error) { return fs.Stat(fss.FS, name) }

func (fss FS) OpenFile(name string, flags int, perm fs.FileMode) (File, error) {
	openFlags := OsFlags(flags)
	if openFlags.IsWrite() || openFlags.CreateIfNotExist() {
		return nil, fs.ErrInvalid
	}
	file, err := fss.FS.Open(name)
	if err != nil {
		return nil, err
	}

	node := &FSSFile{fileName: name, File: file}
	node.ressek = func() (err error) {
		node.File, err = fss.FS.Open(name)
		return
	}
	return node, nil
}
