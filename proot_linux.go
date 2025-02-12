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

const DefaultPtraceFlags = syscall.PTRACE_O_MASK |
	syscall.PTRACE_O_TRACECLONE |
	syscall.PTRACE_O_TRACEEXEC |
	syscall.PTRACE_O_TRACEEXIT |
	syscall.PTRACE_O_TRACEFORK |
	syscall.PTRACE_O_TRACESYSGOOD |
	syscall.PTRACE_O_TRACEVFORK |
	syscall.PTRACE_O_TRACEVFORKDONE

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

	proot.Pid = &ProcessPID{
		PID:     proot.Cmd.Process.Pid,
		Process: proot.Cmd.Process,
		Childs:  map[int]*ProcessPID{},
	}
	waitStart := make(chan struct{})
	go proot.watcherPID(waitStart, proot.Pid, proot.Cmd.Process.Pid)
	<-waitStart
	close(waitStart)
	return err
}

// Watch process and childs to new syscallers and process health
func (proot *PRoot) watcherPID(ccaller chan<- struct{}, proc *ProcessPID, pid int) {
	proot.wait.Add(1) // Add wait group
	defer delete(proc.Childs, pid)
	defer proot.wait.Done()
	defer proc.Kill()
	if ccaller != nil {
		ccaller <- struct{}{}
	}
	for {
		err := error(nil)
		fmt.Fprintf(logFile, "Waiting new pid\n")

		var status syscall.WaitStatus
		if pid, err = syscall.Wait4(pid, &status, 0, nil); err != nil {
			fmt.Fprintf(logFile, "Error waiting for process: %v\n", err)
			proot.pidsErros[pid] = &ProcessPID{
				PID:    pid,
				Err:    err,
				Childs: proc.Childs,
			}
			return
		}
		fmt.Fprintf(logFile, "\n")
		fmt.Fprintf(logFile, "CoreDump: %v, Signal: %v, Exit: %v, Stoped: %v, Trap: %v\n",
			status.CoreDump(),
			status.Signal().String(),
			status.ExitStatus(),
			status.Stopped(),
			status.TrapCause(),
		)
		keep_stopped := true

		if status.Stopped() {
			switch traped := (uint32(status) & 0xfff00) >> 8; traped {
			case uint32(syscall.SIGTRAP) | 0x80:
				// if ((ptracee->as_ptracee).ignore_syscalls || (ptracee->as_ptracee).ignore_loader_syscalls) return false;
				// if (((ptracee->as_ptracee).options & PTRACE_O_TRACESYSGOOD) == 0) event &= ~(0x80 << 8);
				// handledFirst = IS_IN_SYSEXIT(ptracee);
				fmt.Fprintf(logFile, "SIGTRAP %d\n", traped)
			case uint32(syscall.SIGTRAP) | syscall.PTRACE_EVENT_FORK<<8:
				fmt.Fprintf(logFile, "PTRACE_EVENT_FORK %d\n", traped)
			case uint32(syscall.SIGTRAP) | syscall.PTRACE_EVENT_VFORK<<8:
				fmt.Fprintf(logFile, "PTRACE_EVENT_VFORK %d\n", traped)
			case uint32(syscall.SIGTRAP) | syscall.PTRACE_EVENT_VFORK_DONE<<8:
				fmt.Fprintf(logFile, "PTRACE_EVENT_VFORK_DONE %d\n", traped)
			case uint32(syscall.SIGTRAP) | syscall.PTRACE_EVENT_CLONE<<8:
				fmt.Fprintf(logFile, "PTRACE_EVENT_CLONE %d\n", traped)
			case uint32(syscall.SIGTRAP) | syscall.PTRACE_EVENT_EXEC<<8:
				fmt.Fprintf(logFile, "PTRACE_EVENT_EXEC %d\n", traped)
			// case uint32(syscall.SIGTRAP):
				// syscall.PtraceSetOptions(pid, DefaultPtraceFlags)
			default:
				fmt.Fprintf(logFile, "PTRACE_EVENT_UNKNOWN %d\n", traped)
			}
		} else if status.Exited() || status.Signaled() {
			fmt.Fprintf(logFile, "Process %d exited with status %d\n", pid, status.ExitStatus())
			proc.Kill()
			return
		}

		if keep_stopped {
			// Continue execution
			if err := syscall.PtraceCont(pid, 0); err != nil {
				fmt.Fprintf(logFile, "Error continuing process: %v\n", err)
				proot.pidsErros[pid] = &ProcessPID{
					PID:    pid,
					Err:    err,
					Childs: proc.Childs,
				}
				return
			}
			continue
		}

		var Regs syscall.PtraceRegs
		if err := syscall.PtraceGetRegs(pid, &Regs); err != nil {
			fmt.Fprintf(logFile, "Error getting registers: %v\n", err)
			proot.pidsErros[pid] = &ProcessPID{
				PID:    pid,
				Err:    err,
				Childs: proc.Childs,
			}
			return
		}

		fmt.Fprintf(logFile, "Registers: %+v\n", Regs)
		if err := proot.handlerSyscall(pid, status, &Regs); err != nil {
			fmt.Fprintf(logFile, "Error processing syscall: %v\n", err)
			proot.pidsErros[pid] = &ProcessPID{
				PID:    pid,
				Err:    err,
				Childs: proc.Childs,
			}
			return
		}

		if status.Stopped() {
			// Continue execution
			if err := syscall.PtraceCont(pid, 0); err != nil {
				fmt.Fprintf(logFile, "Error continuing process: %v\n", err)
				proot.pidsErros[pid] = &ProcessPID{
					PID:    pid,
					Err:    err,
					Childs: proc.Childs,
				}
				return
			}
		} else {
			syscall.PtraceSyscall(pid, 0)
		}
	}
}
