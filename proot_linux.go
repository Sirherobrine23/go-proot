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

	proot.Pid = &Tracee{
		PID:    proot.Cmd.Process.Pid,
		VPID:   proot.vpids,
		Childs: map[int]*Tracee{},
	}

	started := make(chan struct{}, 1)
	go proot.eventLoop(started)
	<-started
	close(started)
	return err
}

// Watch process and childs to new syscallers and process health
func (proot *PRoot) eventLoop(ccaller chan<- struct{}) {
	proot.wait.Add(1) // Add wait group
	ccaller <- struct{}{}
	defer proot.Pid.Kill() // Kill process and childs
	defer proot.wait.Done() // Done event loop

	for {
		var traceeStatus syscall.WaitStatus
		pid, err := syscall.Wait4(proot.Pid.PID, &traceeStatus, syscall.WALL, nil)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			proot.Pid.Err = err
			proot.Pid.Terminated = true
			proot.Pid.Running = false
			proot.Pid.Kill() // Kill process and childs
			return
		}
		tracee := proot.Pid.getTracee(proot, pid, true)
		if tracee == nil {
			panic("Tracee not found")
		}
		tracee.Running = false
		fmt.Fprintf(logFile, "PID: %d, VPID: %d, Status: %x\n", tracee.PID, tracee.VPID, traceeStatus)

		if tracee.AsPtracee.Ptracer != nil {
			keepStopped, err := tracee.HandlePtraceeEvent(int(traceeStatus))
			if err != nil {
				panic(err)
			} else if keepStopped {
				continue
			}
		}

		signal, err := tracee.HandleTraceeEvent(int(traceeStatus))
		if err == nil {
			_ = tracee.RestartTracee(signal)
		}
		if err != nil {
			panic(err)
		}
	}
}
