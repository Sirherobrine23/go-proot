package proot

import (
	"fmt"
	"os"
	"syscall"

	"sirherobrine23.com.br/go-bds/go-proot/filesystem"
)

const (
	_ int = iota
	SigStopIgnored
	SigStopAllowed
	SigStopPending
)

type FSNamespace struct {
	filesystem.File
	CWD string
}

type AsPtracer struct {
	NBPtracees uint
	Zombies    []*Tracee

	WaitPID     int
	WaitOptions uint32

	// Waits:
	//   - DOESNT_WAIT     = 0
	//   - WAITS_IN_KERNEL = 1
	//   - WAITS_IN_PROOT  = 2
	WaitsIn uint8
}

type AsPtracee struct {
	Ptracer *Tracee

	TracingStarted      bool
	IngoreLoaderSyscall bool
	IngoreSyscall       bool
	IsZombie            bool
	Options             int

	Event4 struct {
		Proot struct {
			Value   int
			Pending bool
		}
		Ptracer struct {
			Value   int
			Pending bool
		}
	}
}

type Tracee struct {
	Err error // If the process has an error

	Parent *Tracee

	PID        int  // PID of the process
	VPID       int  // Process ID of the process
	Running    bool // is it currently running or not?
	Terminated bool // has the process terminated to free
	Clone      bool // Is it a "clone", i.e has the same parent as its creator.

	AsPtracer AsPtracer // Support for ptrace emulation (tracer side).
	AsPtracee AsPtracee // Support for ptrace emulation (tracee side).

	RegsIsChanged bool                  // Has the register changed?
	Regs          []*syscall.PtraceRegs // Registers of the process.

	// Current status:
	//        0: enter syscall
	//        1: exit syscall no error
	//   -errno: exit syscall with error.
	Status int

	RestartHow int
	Sigstop    int

	FS filesystem.File // Information related to a file-system name-space.

	// Path to the executable, à la /proc/self/exe.
	Execute, NewExecute string

	// Runner information
	Qemu *Binfmt

	Childs map[int]*Tracee // Childs of the process
}

func (proc *Tracee) Kill() error { return proc.Signal(os.Kill) }

func (proc *Tracee) Signal(sig os.Signal) error {
	for _, child := range proc.Childs {
		child.Signal(sig)
	}
	prosses, err := os.FindProcess(proc.PID)
	if err != nil {
		return err
	}
	return prosses.Signal(sig)
}

func (proc *Tracee) getTracee(proot *PRoot, pid int, create bool) *Tracee {
	if proc.Childs == nil {
		proc.Childs = map[int]*Tracee{}
	}

	if proc.PID == pid {
		return proc
	} else if _, ok := proc.Childs[pid]; !ok {
		oldProc, newProc := (*Tracee)(nil), proc
		for newProc != nil {
			oldProc = newProc
			newProc = oldProc.getTracee(proot, pid, false)
		}
	}

	if create {
		vpid := proot.vpids
		proot.vpids += 1
		proc.Childs[pid] = &Tracee{
			PID:    pid,
			VPID:   vpid,
			Childs: map[int]*Tracee{},
		}
		return proc.Childs[pid]
	}
	return nil
}

func (ptracee *Tracee) HandlePtraceeEvent(event int) (keepStopped bool, err error) {
	ptracer := ptracee.AsPtracee.Ptracer
	if ptracer == nil {
		return false, nil
	}
	ptracee.AsPtracee.Event4.Proot.Value = event
	ptracee.AsPtracee.Event4.Proot.Pending = true
	keepStopped = true

	handledByProotFirst := false
	if syscall.WaitStatus(event).Stopped() {
		switch (event & 0xfff00) >> 8 {
		case int(syscall.SIGTRAP) | 0x80:
			if ptracee.AsPtracee.IngoreSyscall || ptracee.AsPtracee.IngoreLoaderSyscall {
				return false, nil
			}
			if ptracee.AsPtracee.Options&syscall.PTRACE_O_TRACESYSGOOD == 0 {
				event &= ^(0x80 << 8)
			}
			handledByProotFirst = ptracee.Status == 0
		case int(syscall.SIGTRAP) | syscall.PTRACE_EVENT_FORK<<8:
			if (ptracee.AsPtracee.Options & syscall.PTRACE_O_TRACEFORK) == 0 {
				return false, nil
			}
			ptracee.AsPtracee.TracingStarted = true
			handledByProotFirst = true
		case int(syscall.SIGTRAP) | syscall.PTRACE_EVENT_VFORK<<8:
			if (ptracee.AsPtracee.Options & syscall.PTRACE_O_TRACEVFORK) == 0 {
				return false, nil
			}
			ptracee.AsPtracee.TracingStarted = true
			handledByProotFirst = true
		case int(syscall.SIGTRAP) | syscall.PTRACE_EVENT_VFORK_DONE<<8:
			if (ptracee.AsPtracee.Options & syscall.PTRACE_O_TRACEVFORKDONE) == 0 {
				return false, nil
			}
			ptracee.AsPtracee.TracingStarted = true
			handledByProotFirst = true
		case int(syscall.SIGTRAP) | syscall.PTRACE_EVENT_CLONE<<8:
			if (ptracee.AsPtracee.Options & syscall.PTRACE_O_TRACECLONE) == 0 {
				return false, nil
			}
			ptracee.AsPtracee.TracingStarted = true
			handledByProotFirst = true
		case int(syscall.SIGTRAP) | syscall.PTRACE_EVENT_EXIT<<8:
			if (ptracee.AsPtracee.Options & syscall.PTRACE_O_TRACEEXIT) == 0 {
				return false, nil
			}
			ptracee.AsPtracee.TracingStarted = true
			handledByProotFirst = true
		case int(syscall.SIGTRAP) | syscall.PTRACE_EVENT_EXEC<<8:
			if (ptracee.AsPtracee.Options & syscall.PTRACE_O_TRACEEXIT) == 0 {
				return false, nil
			}
			ptracee.AsPtracee.TracingStarted = true
			handledByProotFirst = true
		default:
			ptracee.AsPtracee.TracingStarted = true
		}
	} else if syscall.WaitStatus(event).Exited() || syscall.WaitStatus(event).Signaled() {
		keepStopped = false
		ptracee.AsPtracee.TracingStarted = true
	}

	if !ptracee.AsPtracee.TracingStarted {
		return false, nil
	}

	if handledByProotFirst {
		ptracee.AsPtracee.Event4.Proot.Value, err = ptracee.HandleTraceeEvent(ptracee.AsPtracee.Event4.Proot.Value)
		if err != nil {
			return false, err
		} else if ptracee.AsPtracee.Event4.Proot.Value == 0 {
			return false, fmt.Errorf("cannot get signal to %d", ptracee.PID)
		}
	}

	ptracee.AsPtracee.Event4.Ptracer.Pending = true
	ptracee.AsPtracee.Event4.Ptracer.Value = event

	// Notify asynchronously the ptracer about this event, as the kernel does.
	syscall.Kill(ptracee.PID, syscall.SIGCHLD)

	// Note: wait_pid is set in translate_wait_exit() if no ptracee event was pending when the ptracer started to wait.
	if (ptracee.AsPtracer.WaitPID == -1 || ptracee.AsPtracer.WaitPID == ptracee.PID) && ((((ptracee.AsPtracer.WaitOptions) & syscall.WALL) != 0) || ((((ptracee.AsPtracer.WaitOptions) & syscall.WCLONE) != 0) && ptracee.Clone) || ((((ptracee.AsPtracer.WaitOptions) & syscall.WCLONE) == 0) && !ptracee.Clone)) {
		result, err := UpdateWaitStatus(ptracer, ptracee)
		if err != nil {
			return false, err
		} else if result != 0 {
			ptracee.PokeReg(RegSYSARG_RESULT, result)
		}

		/* Write ptracer's register cache back.  */
		ptracee.PushRegs()

		// Restart the ptracer.
		ptracee.AsPtracer.WaitPID = 0

		restarted := false
		// restarted = restart_tracee(ptracer, 0);

		if !restarted {
			keepStopped = false
		}
	}

	return
}

func UpdateWaitStatus(ptracer, ptracee *Tracee) (result int, err error) {
	// Special case: the Linux kernel reports the terminating
	// event issued by a process to both its parent and its
	// tracer, except when they are the same.  In this case the
	// Linux kernel reports the terminating event only once to the
	// tracing parent ...
	if (ptracee.AsPtracee.Ptracer == ptracer.Parent) && (syscall.WaitStatus(ptracee.AsPtracee.Event4.Ptracer.Value).Exited() || syscall.WaitStatus(ptracee.AsPtracee.Event4.Ptracer.Value).Signaled()) {
		// ... So hide this terminating event (toward its
		// tracer, ie. PRoot) and make the second one appear
		// (towards its parent, ie. the ptracer).  This will
		// ensure its exit status is collected from a kernel
		// point-of-view (ie. it doesn't stay a zombie
		// forever).
		ptracer.RestartOrigalSyscall()
		ptracer.DetachFromPtracer()
		return 0, nil
	}

	address := ptracee.PeekReg(RegVersionORIGINAL, RegSYSARG_2)
	if address != 0 {
		err := ptracee.PokeInt32(address, ptracee.AsPtracee.Event4.Ptracer.Value)
		if err != nil {
			return 0, err
		}
	}
	ptracee.AsPtracee.Event4.Ptracer.Pending = false
	if ptracee.AsPtracee.IsZombie {
		ptracee.DetachFromPtracer()
	}
	return ptracee.PID, err
}

const (
	RegSYSARG_NUM int = iota
	RegSYSARG_1
	RegSYSARG_2
	RegSYSARG_3
	RegSYSARG_4
	RegSYSARG_5
	RegSYSARG_6
	RegSYSARG_RESULT
	RegSTACK_POINTER
	RegINSTR_POINTER
	RegRTLD_FINI
	RegSTATE_FLAGS
	RegUSERARG_1
)

const (
	RegVersionCURRENT int = iota
	RegVersionORIGINAL
	RegVersionMODIFIED
	RegVersionNB_REG_VERSION
)

func (ptracee *Tracee) PeekReg(Version, reg int) int {
	panic("not implemented")
}

func (ptracee *Tracee) PokeInt32(reg, value int) error { panic("not implemented") }
func (ptracee *Tracee) PushRegs()                      { panic("not implemented") }
func (ptracee *Tracee) PokeReg(reg, value int) error   { panic("not implemented") }

func (ptracee *Tracee) DetachFromPtracer() {
	ptracer := ptracee.AsPtracee.Ptracer
	ptracee.AsPtracee.Ptracer = nil
	if ptracer.AsPtracer.NBPtracees > 0 {
		ptracer.AsPtracer.NBPtracees--
	}
}

func (ptracee *Tracee) RestartOrigalSyscall() error {

	return nil
}

func (ptracee *Tracee) HandleTraceeEvent(event int) (int, error) {
	return -1, nil
}

func (ptracee *Tracee) RestartTracee(signal int) error {
	if ptracee.AsPtracee.Ptracer.AsPtracer.WaitPID != 0 || signal == -1 {
		return nil
	}

	ptrace := func(request int, pid int, addr uintptr, data uintptr) (err error) {
		_, _, e1 := syscall.Syscall6(syscall.SYS_PTRACE, uintptr(request), uintptr(pid), uintptr(addr), uintptr(data), 0, 0)
		if e1 != 0 {
			err = syscall.Errno(e1)
		}
		return nil
	}

	if err := ptrace(ptracee.RestartHow, ptracee.PID, 0, uintptr(signal)); err != nil {
		return err
	}

	fmt.Fprintf(logFile, "VPID: %d, restarted using signal %d\n", ptracee.VPID, signal)
	ptracee.RestartHow = 0
	ptracee.Running = true
	return nil
}
