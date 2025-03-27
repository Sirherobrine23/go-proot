//go:build linux || android

package proot

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func (proot *Proot) loopEvent() {
	for {
		var traceeStatus unix.WaitStatus
		pid, err := unix.Wait4(proot.Cmd.Process.Pid, &traceeStatus, unix.WALL, nil)
		if err != nil {
			proot.Err = err
			return
		}

		proot.handleTraceeEventKernel(pid, traceeStatus)
	}
}

func (proot *Proot) handleTraceeEventKernel(pid int, traceeStatus unix.WaitStatus) int {
	var status int
	// seccomp_detected, seccomp_enabled := false, false

	if traceeStatus.Exited() || traceeStatus.Signaled() {
		switch {
		case traceeStatus.Exited():
			fmt.Printf("%d: exit code: %d\n", pid, traceeStatus.ExitStatus())
		case traceeStatus.Signaled():
			fmt.Printf("%d: Signal: %s\n", pid, traceeStatus.Signal())
		}
		return 0
	} else if traceeStatus.Stopped() {
	loopSwitch:
		for {
			switch traceeStatus.StopSignal() {
			case unix.SIGTRAP:
				defaultPtraceOptions := unix.PTRACE_O_TRACESYSGOOD |
					unix.PTRACE_O_TRACEFORK |
					unix.PTRACE_O_TRACEVFORK |
					unix.PTRACE_O_TRACEVFORKDONE |
					unix.PTRACE_O_TRACEEXEC |
					unix.PTRACE_O_TRACECLONE |
					unix.PTRACE_O_TRACEEXIT

				if err := unix.PtraceSetOptions(pid, defaultPtraceOptions|unix.PTRACE_O_TRACESECCOMP); err != nil {
					if err := unix.PtraceSetOptions(pid, defaultPtraceOptions); err != nil {
						proot.Err = err
						return 0
					}
				}
			case unix.SIGTRAP | 0x80:
				// if (tracee->exe == NULL) {
				// 	tracee->restart_how = PTRACE_CONT; /* SYSCALL OR CONT */
				// 	return 0;
				// }

				// translate_syscall(tracee);
			case unix.SIGTRAP | unix.PTRACE_EVENT_VFORK<<8:
				// (void)new_child(tracee, unix.CLONE_VFORK)
				break loopSwitch
			case unix.SIGTRAP | unix.PTRACE_EVENT_FORK<<8, unix.SIGTRAP | unix.PTRACE_EVENT_CLONE<<8:
				// (void)new_child(tracee, 0)
				break loopSwitch
			case unix.SIGTRAP | unix.PTRACE_EVENT_VFORK_DONE<<8, unix.SIGTRAP | unix.PTRACE_EVENT_EXEC<<8, unix.SIGTRAP | unix.PTRACE_EVENT_EXIT<<8:
				// signal = 0
				break loopSwitch
			case unix.SIGSTOP:
				// Stop this tracee until PRoot has received the EVENT_*FORK|CLONE notification.
				// if (tracee->exe == NULL) {
				// 	tracee->sigstop = SIGSTOP_PENDING;
				// 	signal = -1;
				// }

				// For each tracee, the first SIGSTOP is only used to notify the tracer.
				// if (tracee->sigstop == SIGSTOP_IGNORED) {
				// 	tracee->sigstop = SIGSTOP_ALLOWED;
				// 	signal = 0;
				// }
				break loopSwitch
			}
		}
	}

	return status
}

// new_child()
// https://sirherobrine23.com.br/proot-me/proot/src/commit/5f780cba57ce7ce557a389e1572e0d30026fcbca/src/tracee/tracee.c#L381-L587
