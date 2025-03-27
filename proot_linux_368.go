//go:build linux && 386
package proot

import "golang.org/x/sys/unix"

func (proot *Proot) getTrace(pid int) (*unix.PtraceRegs, error) {
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return nil, err
	}
	return &regs, nil
}