package tracee

import "sirherobrine23.com.br/go-bds/go-proot/filesystem"

type FileSystemNameSpace struct {
	// Current working directory, à la /proc/self/pwd.
	Cwd string

	Binding filesystem.Binding
}

func New(pid int, vpid uint64) *Tracee {
	return &Tracee{
		Pid:  pid,
		VPid: vpid,
	}
}

type Tracee struct {
	// Link for the list of all tracees.
	Link *Tracee

	// Process identifier.
	Pid int

	// Unique tracee identifier.
	VPid uint64

	// Is it currently running or not?
	Running bool

	// Is this tracee ready to be freed?  TODO: move to a l
	// dedicated to terminated tracees instead.
	Terminated bool

	// Whether termination of this tracee implies an immediate k
	// of all tracees.
	KillallOnExit bool

	// Parent of this tracee, NULL if none.
	Parent *Tracee

	// Is it a "clone", i.e has the same parent as its creator.
	Clone bool

	// Support for ptrace emulation (tracer side).
	AsPtracer struct {
		nbPtracees int
		zombies    *Tracee

		waitPid     int
		waitOptions uint64

		waitsIn int
	}

	// Support for ptrace emulation (tracee side).
	AsPtracee struct {
		Ptracer *Tracee

		Event4 struct {
			Proot struct {
				value   int
				pending bool
			}
			Ptracer struct {
				value   int
				pending bool
			}
		}

		TracingStarted       bool
		IgnoreLoaderSyscalls bool
		IgnoreSyscalls       bool
		Options              uint64
		IsZombie             bool
	}

	// Current stat
	//        0: enter syscall
	//        1: exit syscall no error
	//   -errno: exit syscall with error.
	Status int

	// Information related to a file-system name-space.
	FS *FileSystemNameSpace

	// Path to the executable, à la /proc/self/exe.
	EXE, NewEXE string

	// Runner command-line.
	Qemu string
}
