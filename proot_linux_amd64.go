//go:build (linux || android) && amd64

package proot

import "golang.org/x/sys/unix"

func (tracee *Tracee) fetchRegs() error {
	return unix.PtraceGetRegs(tracee.PID, &tracee.Regs)
}
