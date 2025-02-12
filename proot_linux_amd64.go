//go:build linux && amd64

package proot

import (
	"fmt"
	"syscall"
)

var ProcessSyscalls = map[int](func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error){
	syscall.SYS_EXECVE: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		regAddr := uintptr(regs.Rdi)
		if regAddr == 0 {
			return syscall.PtraceSyscall(pid, 0)
		}
		path, err := ReadString(pid, regAddr)
		if err != nil {
			fmt.Fprintf(logFile, "EXECVE: Error reading path: %v\n", err)
			return syscall.PtraceSyscall(pid, 0)
		}
		fmt.Fprintf(logFile, "EXECVE: Path=%q\n", path)

		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_READ: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		fd := int(regs.Rdi)
		bufAddr := uintptr(regs.Rsi)
		count := int(regs.Rdx)

		fmt.Fprintf(logFile, "READ: fd=%d, buf=0x%x, count=%d\n", fd, bufAddr, count)

		if bufAddr == 0 || count <= 0 {
			fmt.Fprintf(logFile, "READ: Invalid buffer or count\n")
			return syscall.PtraceSyscall(pid, 0)
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
		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_WRITE: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		fd := int(regs.Rdi)
		bufAddr := uintptr(regs.Rsi)
		count := int(regs.Rdx)

		fmt.Fprintf(logFile, "WRITE: fd=%d, buf=0x%x, count=%d\n", fd, bufAddr, count)

		if bufAddr == 0 || count <= 0 {
			fmt.Fprintf(logFile, "WRITE: Invalid buffer or count\n")
			return syscall.PtraceSyscall(pid, 0)
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
		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_CLOSE: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		fd := int(regs.Rdi) // File descriptor being closed
		fmt.Fprintf(logFile, "CLOSE: fd=%d\n", fd)

		// Optional: Prevent closing specific FDs
		if fd == 1 { // Example: Prevent closing stdout
			fmt.Fprintf(logFile, "CLOSE: Blocking close of fd=%d\n", fd)
			regs.Rax = 0 // Simulate failure
			syscall.PtraceSetRegs(pid, regs)
		}
		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_ACCESS: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		if regs.Rdi == 0 {
			return syscall.PtraceSyscall(pid, 0) // Invalid path pointer
		}

		// Read file path from process memory
		path, err := ReadString(pid, uintptr(regs.Rdi))
		if err != nil {
			fmt.Fprintf(logFile, "ACCESS: Error reading path: %v\n", err)
			return syscall.PtraceSyscall(pid, 0)
		}

		mode := int(regs.Rsi) // Access mode
		fmt.Fprintf(logFile, "ACCESS: Path=%q, Mode=%#x\n", path, mode)

		// Optional: Restrict access to certain files
		if path == "/etc/shadow" {
			fmt.Fprintf(logFile, "ACCESS: Blocking access to %q\n", path)
			regs.Rax = 0 // Simulate access denial
			syscall.PtraceSetRegs(pid, regs)
		}

		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_OPENAT: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		if regs.Rsi == 0 {
			return syscall.PtraceSyscall(pid, 0) // Invalid path pointer
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
		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_FSTAT: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		fd := int(regs.Rdi)
		statAddr := uintptr(regs.Rsi)

		fmt.Fprintf(logFile, "FSTAT: fd=%d, struct addr=0x%x\n", fd, statAddr)

		if statAddr == 0 {
			fmt.Fprintf(logFile, "FSTAT: Invalid struct address\n")
			return syscall.PtraceSyscall(pid, 0)
		}

		// Read struct stat (first 64 bytes for basic fields)
		var statBuf [64]byte
		_, err := syscall.PtracePeekData(pid, statAddr, statBuf[:])
		if err != nil {
			fmt.Fprintf(logFile, "Error reading fstat struct: %v\n", err)
		} else {
			fmt.Fprintf(logFile, "FSTAT: stat struct raw data: %x\n", statBuf)
		}
		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_NEWFSTATAT: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
		dirfd := int(regs.Rdi)
		path, err := ReadString(pid, uintptr(regs.Rsi))
		if err != nil {
			fmt.Fprintf(logFile, "NEWFSTATAT: Error reading path: %v\n", err)
			return syscall.PtraceSyscall(pid, 0)
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
		return syscall.PtraceSyscall(pid, 0)
	},
	syscall.SYS_CLONE: func(proot *PRoot, pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
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
		return syscall.PtraceSyscall(pid, 0)
	},
}

func (proot *PRoot) handlerSyscall(pid int, traceeStatus syscall.WaitStatus, regs *syscall.PtraceRegs) error {
	sysID := int(regs.Orig_rax)
	fmt.Fprintf(logFile, "Syscall (%d):\t%q\n", sysID, mapped[sysID])
	defer fmt.Fprintln(logFile)
	if handler, ok := ProcessSyscalls[sysID]; ok {
		return handler(proot, pid, traceeStatus, regs)
	}
	return syscall.PtraceSyscall(pid, 0)
}
