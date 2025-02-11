package proot

import "debug/elf"

type Binfmt struct {
	Header   elf.FileHeader // File header info
	Emulator []string       // Program command + args
}
