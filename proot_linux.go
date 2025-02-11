//go:build linux

package proot

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

/*
Start process in backgroud with support to pass os.Stdout, os.Stderr and os.Stdin to process to manipulate TTY
*/
func (proot *PRoot) start() error {
	err, stdin, stdout, stderr := error(nil), proot.Stdin.(*os.File), proot.Stdout.(*os.File), proot.Stderr.(*os.File)
	execPath := ""
	if proot.Command[0][0] == '/' {
		_, err := proot.Rootfs.Stat(proot.Command[0])
		if err != nil {
			return err
		}
		execPath = proot.Rootfs.HostPath(proot.Command[0])
	} else {
		path := os.Getenv("PATH")
		for _, dir := range filepath.SplitList(path) {
			if dir == "" {
				// Unix shell semantics: path element "" means "."
				dir = "."
			}
			path := filepath.Join(dir, proot.Command[0])
			if _, err := proot.Rootfs.Stat(path); err == nil {
				execPath = path
				break
			} else if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}

	proot.Cmd = exec.Command(execPath, proot.Command[1:]...)
	proot.Cmd.Stdin = stdin
	proot.Cmd.Stdout = stdout
	proot.Cmd.Stderr = stderr
	proot.Cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true, // Start process in traceable mode
	}

	if err := proot.Cmd.Start(); err != nil {
		return err
	}

	proot.newPID = proot.Cmd.Process.Pid
	prootDone := make(chan error)
	proot.done = prootDone

	syscall.PtraceSetOptions(proot.newPID, syscall.PTRACE_O_TRACESYSGOOD|syscall.PTRACE_O_TRACEEXIT)
	syscall.PtraceSyscall(proot.newPID, 0)

	go func() {
		defer close(prootDone)
		for {
			select {
			case <-prootDone:
				return
			default:
				var treeStatus syscall.WaitStatus
				wpid, err := syscall.Wait4(proot.Cmd.Process.Pid, &treeStatus, 0, nil)
				if err != nil {
					prootDone <- err
					return
				}

				_ = syscall.PtraceSetOptions(wpid, syscall.PTRACE_O_TRACESYSGOOD)

				var regs syscall.PtraceRegs
				err = syscall.PtraceGetRegs(wpid, &regs)
				if err != nil {
					prootDone <- err
				}
				proot.handlerSyscall(wpid, &treeStatus, &regs)
			}
		}
	}()

	return err
}

// var logFile = os.Stdeerr
var logFile, _ = os.Create("./proot.log")

func WriteString(pid int, addr uintptr, newStr string) error {
	b := append([]byte(newStr), 0) // Null-terminate
	_, err := syscall.PtracePokeData(pid, addr, b)
	return err
}

func ReadString(pid int, addr uintptr) (string, error) {
	var data []byte
	var buf [8]byte // 8 bytes at a time
	for {
		_, err := syscall.PtracePeekData(pid, addr, buf[:])
		if err != nil {
			return "", fmt.Errorf("PtracePeekData failed at %x: %v", addr, err)
		}

		for _, b := range buf {
			if b == 0 {
				return string(data), nil
			}
			data = append(data, b)
		}

		addr += uintptr(len(buf))
	}
}

func (proot *PRoot) handlerSyscall(pid int, traceeStatus *syscall.WaitStatus, regs *syscall.PtraceRegs) error {
	sysID := int(regs.Orig_rax)
	defer fmt.Fprintln(logFile)
	switch sysID {
	default:
		fmt.Fprintf(logFile, "Syscall (%d):\t%q\n", sysID, mapped[sysID])
	case syscall.SYS_EXECVE:
		if !traceeStatus.Stopped() || traceeStatus.TrapCause() != syscall.PTRACE_EVENT_FORK || regs.Rsi == 0 {
			break
		}
		data, _ := ReadString(pid, uintptr(regs.Rsi))
		fmt.Fprintf(logFile, "\nCommand: %s\n", data)
	case syscall.SYS_CLOSE:
		fd := int(regs.Rdi) // File descriptor being closed
		fmt.Fprintf(logFile, "CLOSE: fd=%d\n", fd)

		// Optional: Prevent closing specific FDs
		if fd == 1 { // Example: Prevent closing stdout
			fmt.Fprintf(logFile, "CLOSE: Blocking close of fd=%d\n", fd)
			regs.Rax = 0 // Simulate failure
			syscall.PtraceSetRegs(pid, regs)
		}
	case syscall.SYS_ACCESS:
		if regs.Rdi == 0 {
			break // Invalid path pointer
		}

		// Read file path from process memory
		path, err := ReadString(pid, uintptr(regs.Rdi))
		if err != nil {
			fmt.Fprintf(logFile, "ACCESS: Error reading path: %v\n", err)
			break
		}

		mode := int(regs.Rsi) // Access mode
		fmt.Fprintf(logFile, "ACCESS: Path=%q, Mode=%#x\n", path, mode)

		// Optional: Restrict access to certain files
		if path == "/etc/shadow" {
			fmt.Fprintf(logFile, "ACCESS: Blocking access to %q\n", path)
			regs.Rax = 0 // Simulate access denial
			syscall.PtraceSetRegs(pid, regs)
		}

	case syscall.SYS_OPENAT:
		if regs.Rsi == 0 {
			break // Invalid path pointer
		}

		// Read directory FD
		dirfd := int(regs.Rdi)
		if dirfd == -100 {
			fmt.Fprintf(logFile, "OPENAT: Using AT_FDCWD\n")
		} else {
			fmt.Fprintf(logFile, "OPENAT: dirfd=%d\n", dirfd)
		}

		// Read file path from traced process memory
		path, err := ReadString(pid, uintptr(regs.Rsi))
		if err != nil {
			fmt.Fprintf(logFile, "Error reading path: %v\n", err)
		} else {
			fmt.Fprintf(logFile, "OPENAT: Path=%q\n", path)
		}

		// Read file flags
		flags := int(regs.Rdx)
		fmt.Fprintf(logFile, "OPENAT: Flags=%#x\n", flags)

		// Read mode if O_CREAT is set
		var mode int
		if flags&syscall.O_CREAT != 0 {
			mode = int(regs.R10)
			fmt.Fprintf(logFile, "OPENAT: Mode=%#o\n", mode)
		}
	case syscall.SYS_FSTAT:
		fd := int(regs.Rdi)
		statAddr := uintptr(regs.Rsi)

		fmt.Fprintf(logFile, "FSTAT: fd=%d, struct addr=0x%x\n", fd, statAddr)

		if statAddr == 0 {
			fmt.Fprintf(logFile, "FSTAT: Invalid struct address\n")
			break
		}

		// Read struct stat (first 64 bytes for basic fields)
		var statBuf [64]byte
		_, err := syscall.PtracePeekData(pid, statAddr, statBuf[:])
		if err != nil {
			fmt.Fprintf(logFile, "Error reading fstat struct: %v\n", err)
		} else {
			fmt.Fprintf(logFile, "FSTAT: stat struct raw data: %x\n", statBuf)
		}

	case syscall.SYS_READ:
		fd := int(regs.Rdi)
		bufAddr := uintptr(regs.Rsi)
		count := int(regs.Rdx)

		fmt.Fprintf(logFile, "READ: fd=%d, buf=0x%x, count=%d\n", fd, bufAddr, count)

		if bufAddr == 0 || count <= 0 {
			fmt.Fprintf(logFile, "READ: Invalid buffer or count\n")
			break
		}

		// Read data AFTER syscall executes (at syscall exit)
		var readBuf []byte = make([]byte, count)
		if err := syscall.PtraceGetRegs(pid, regs); err == nil {
			bytesRead := int(regs.Rax) // RAX contains return value
			if bytesRead > 0 {
				_, err := syscall.PtracePeekData(pid, bufAddr, readBuf[:bytesRead])
				if err == nil {
					fmt.Fprintf(logFile, "READ: Data=%q\n", string(readBuf[:bytesRead]))
				} else {
					fmt.Fprintf(logFile, "READ: Error reading data: %v\n", err)
				}
			}
		}

	case syscall.SYS_WRITE:
		fd := int(regs.Rdi)
		bufAddr := uintptr(regs.Rsi)
		count := int(regs.Rdx)

		fmt.Fprintf(logFile, "WRITE: fd=%d, buf=0x%x, count=%d\n", fd, bufAddr, count)

		if bufAddr == 0 || count <= 0 {
			fmt.Fprintf(logFile, "WRITE: Invalid buffer or count\n")
			break
		}

		// Read data to be written
		writeBuf := make([]byte, count)
		_, err := syscall.PtracePeekData(pid, bufAddr, writeBuf)
		if err == nil {
			fmt.Fprintf(logFile, "WRITE: Data=%q\n", string(writeBuf))
		} else {
			fmt.Fprintf(logFile, "WRITE: Error reading data: %v\n", err)
		}

		// Modify output before it's written (example: censor text)
		if string(writeBuf) == "badword" {
			newBuf := []byte("*****")
			syscall.PtracePokeData(pid, bufAddr, newBuf)
			fmt.Fprintf(logFile, "WRITE: Data modified to: %q\n", string(newBuf))
		}
	case syscall.SYS_NEWFSTATAT:
		dirfd := int(regs.Rdi)
		path, err := ReadString(pid, uintptr(regs.Rsi))
		if err != nil {
			fmt.Fprintf(logFile, "NEWFSTATAT: Error reading path: %v\n", err)
			break
		}

		statAddr := uintptr(regs.Rdx)
		flags := int(regs.R10)

		fmt.Fprintf(logFile, "NEWFSTATAT: dirfd=%d, path=%q, statbuf=0x%x, flags=%#x\n",
			dirfd, path, statAddr, flags)

		// Optional: Block access to specific files
		if path == "/etc/passwd" {
			fmt.Fprintf(logFile, "NEWFSTATAT: Blocking access to %q\n", path)
			regs.Rax = 0 // Simulate failure
			syscall.PtraceSetRegs(pid, regs)
		}
	case syscall.SYS_CLONE:
		flags := regs.Rdi
		childStack := uintptr(regs.Rsi)
		ptid := uintptr(regs.Rdx)
		ctid := uintptr(regs.R10)
		newtls := uintptr(regs.R8)

		fmt.Fprintf(logFile, "CLONE: flags=%#x, child_stack=0x%x, ptid=0x%x, ctid=0x%x, newtls=0x%x\n",
			flags, childStack, ptid, ctid, newtls)

		// Optional: Restrict process creation
		if flags&syscall.CLONE_NEWPID != 0 {
			fmt.Fprintf(logFile, "CLONE: Blocking new PID namespace creation\n")
			regs.Rax = 0 // Simulate failure
			syscall.PtraceSetRegs(pid, regs)
		}

	}

	return syscall.PtraceSyscall(pid, 0)
}
