// Go-Proot is proot implemententio in golang
//
// Original tool: https://github.com/proot-me/proot
package proot

import (
	"io"
	"os/exec"

	"golang.org/x/sys/unix"
)

// chroot, mount --bind, and binfmt_misc without privilege/setup for Linux/Android directly from golang
type Proot struct {
	// The specified path typically contains a Linux distribution where
	// all new programs will be confined.  The default rootfs is /
	// when none is specified, this makes sense when the bind mechanism
	// is used to relocate host files and directories.
	Rootfs string

	// This option makes any file or directory of the host rootfs
	// accessible in the confined environment just as if it were part of
	// the guest rootfs.
	//
	// "Fake path" => "Host path"
	Binds map[string]string

	// Execute guest programs through QEMU as specified by command.
	//
	// Each time a guest program is going to be executed, PRoot inserts
	// the QEMU user-mode command in front of the initial request.
	// That way, guest programs actually run on a virtual guest CPU
	// emulated by QEMU user-mode.  The native execution of host programs
	// is still effective and the whole host rootfs is bound to
	// /host-rootfs in the guest environment.
	Qemu string

	// Make current kernel appear as kernel release.
	//
	// If a program is run on a kernel older than the one expected by its
	// GNU C library, the following error is reported: "FATAL: kernel too
	// old".  To be able to run such programs, PRoot can emulate some of
	// the features that are available in the kernel release specified by
	// *string* but that are missing in the current kernel.
	KernelRelease *unix.Utsname

	// Make current user and group.
	//
	// This option makes the current user and group appear as uid and
	// gid.  Likewise, files actually owned by the current user and
	// group appear as if they were owned by uid and gid instead.
	UID, GID int

	// Map ports to others.
	//
	// This option makes PRoot intercept bind and connect system calls,
	// and change the port they use. The port map is specified
	// with the syntax: -b *port_in*:*port_out*. For example,
	// an application that runs a MySQL server binding to 5432 wants
	// to cohabit with other similar application, but doesn't have an
	// option to change its port. PRoot can be used here to modify
	// this port: proot -p 5432:5433 myapplication. With this command,
	// the MySQL server will be bound to the port 5433.
	// This command can be repeated multiple times to map multiple ports.
	Port map[int16]int16

	// Env specifies the environment of the process.
	// Each entry is of the form "key=value".
	// If Env is nil, the new process uses the current process's
	// environment.
	// If Env contains duplicate environment keys, only the last
	// value in the slice for each duplicate key is used.
	Env []string

	// Set the initial working directory.
	//
	// Some programs expect to be launched from a given directory but do
	// not perform any chdir by themselves.  This option avoids the
	// need for running a shell and then entering the directory manually.
	Dir string

	// Command and args to execute programer
	Command []string

	// Stdin specifies the process's standard input.
	//
	// If Stdin is nil, the process reads from the null device (os.DevNull).
	//
	// If Stdin is an *os.File, the process's standard input is connected
	// directly to that file.
	//
	// Otherwise, during the execution of the command a separate
	// goroutine reads from Stdin and delivers that data to the command
	// over a pipe. In this case, Wait does not complete until the goroutine
	// stops copying, either because it has reached the end of Stdin
	// (EOF or a read error), or because writing to the pipe returned an error,
	// or because a nonzero WaitDelay was set and expired.
	Stdin io.Reader

	// Stdout and Stderr specify the process's standard output and error.
	//
	// If either is nil, Run connects the corresponding file descriptor
	// to the null device (os.DevNull).
	//
	// If either is an *os.File, the corresponding output from the process
	// is connected directly to that file.
	//
	// Otherwise, during the execution of the command a separate goroutine
	// reads from the process over a pipe and delivers that data to the
	// corresponding Writer. In this case, Wait does not complete until the
	// goroutine reaches EOF or encounters an error or a nonzero WaitDelay
	// expires.
	//
	// If Stdout and Stderr are the same writer, and have a type that can
	// be compared with ==, at most one goroutine at a time will call Write.
	Stdout, Stderr io.Writer

	// Add exec cmd to process proot
	Cmd *exec.Cmd

	Err error
}

func (proot *Proot) Start() error {
	go proot.loopEvent()

	return nil
}

func (proot *Proot) Run() ([]byte, error) {

	return nil, nil
}
