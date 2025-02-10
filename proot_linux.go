//go:build android || linux

package proot

import (
	"os"
	"os/exec"
	"syscall"

	"sirherobrine23.com.br/go-bds/go-proot/kernel/ptrace"
	"sirherobrine23.com.br/go-bds/go-proot/kernel/tracee"
)

func (proot *PRoot) Start() (err error) {
	if proot.sysTracee != nil {
		return nil
	}

	stdin, stdout, stderr := (*os.File)(nil), (*os.File)(nil), (*os.File)(nil)
	if stdout, err = writeToOs(proot.Stdout); err != nil {
		return err
	} else if stderr, err = writeToOs(proot.Stderr); err != nil {
		return err
	} else if stdin, err = readToOs(proot.Stdin); err != nil {
		return err
	}

	execPath, err := exec.LookPath(proot.Command[0])
	if err != nil {
		return err
	}

	pid, err := syscall.ForkExec(execPath, proot.Command, &syscall.ProcAttr{
		Dir: proot.Dir,
		Env: append(os.Environ(), proot.Env...),
		Files: []uintptr{
			stdin.Fd(),
			stdout.Fd(),
			stderr.Fd(),
		},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
		},
	})
	if err != nil {
		return err
	}

	// Add process to PID
	if proot.Process, err = os.FindProcess(pid); err != nil {
		return err
	}

	// Add pid to fist process
	proot.sysTracee = tracee.New(pid, uint64(proot.vpids))

	if err = syscall.PtraceSetOptions(proot.sysTracee.Pid, syscall.PTRACE_O_TRACECLONE); err == nil {
		err = syscall.PtraceSetOptions(proot.sysTracee.Pid, syscall.PTRACE_O_TRACESYSGOOD)
	}
	if err != nil {
		return err
	}

	idd := ptrace.Ptrace(proot.sysTracee.Pid)
	go func() {
		for {
			sysm, err := idd.GetSyscall()
			if err != nil {
				panic(err)
			}
			println("Syscall", int(sysm.Orig_rax))
		}
	}()

	return nil
}
