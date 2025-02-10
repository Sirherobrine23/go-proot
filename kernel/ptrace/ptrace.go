package ptrace

import (
	"syscall"
)

type PtraceRegs syscall.PtraceRegs

func (data PtraceRegs) Syscall() int { return int(data.Orig_rax) }

func (data PtraceRegs) OpenAT(pid int) (string, error) {
	buff := make([]byte, syscall.PathMax)
	count, err := syscall.PtracePeekText(pid, uintptr(data.Rsi), buff)
	if err != nil {
		return "", err
	}
	return string(buff[:count]), nil
}

type Ptrace int

func (pid Ptrace) GetSyscall() (*PtraceRegs, error) {
	var data PtraceRegs
	if err := syscall.PtraceGetRegs(int(pid), (*syscall.PtraceRegs)(&data)); err != nil {
		return nil, err
	}
	return &data, nil
}
