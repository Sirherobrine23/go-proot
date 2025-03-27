package proot

import "golang.org/x/sys/unix"

const HostRootfs string = "/host-rootfs"

// extern Tracee *get_tracee(const Tracee *tracee, pid_t pid, bool create);
// extern Tracee *get_ptracee(const Tracee *ptracer, pid_t pid, bool only_stopped, bool only_with_pevent, word_t wait_options);
// extern Tracee *get_stopped_ptracee(const Tracee *ptracer, pid_t pid, bool only_with_pevent, word_t wait_options);
// extern bool has_ptracees(const Tracee *ptracer, pid_t pid, word_t wait_options);
// extern int new_child(Tracee *parent, word_t clone_flags);
// extern Tracee *new_dummy_tracee(TALLOC_CTX *context);
// extern void terminate_tracee(Tracee *tracee);
// extern void free_terminated_tracees();
// extern int swap_config(Tracee *tracee1, Tracee *tracee2);
// extern void kill_all_tracees();

type Tracee struct {
	Link          []*Tracee // Link for the list of all tracees.
	PID           int       // Process identifier.
	Vpid          int       // Unique tracee identifier.
	Running       bool      // Is it currently running or not?
	Terminated    bool      // Is this tracee ready to be freed?  TODO: move to a list dedicated to terminated tracees instead.
	KillallOnExit bool      // Whether termination of this tracee implies an immediate kill of all tracees.
	Parent        *Tracee   // Parent of this tracee, NULL if none.
	Clone         bool      // Is it a "clone", i.e has the same parent as its creator.

	// Support for ptrace emulation (tracer side).
	AsPtracer struct {
		nb_ptracees int
		Zombies     []*Tracee

		WaitPid, WaitOptions int

		// DOESNT_WAIT = 0,
		// WAITS_IN_KERNEL = 1,
		// WAITS_IN_PROOT = 2,
		WaitsIN int
	}

	// Support for ptrace emulation (tracee side).
	AsPtracee struct {
		Ptrace *Tracee

		Event4 struct {
			Proot, Ptracer struct {
				Value   int
				Pending bool
			}
		}

		TracingStarted       bool
		IgnoreLoaderSyscalls bool
		IgnoreSyscalls       bool
		OPtions              int
		IsZombie             bool
	}

	/* Current status:
	     0: enter syscall
	     1: exit syscall no error
	-errno: exit syscall with error.  */
	Status int

	// How this tracee is restarted.
	RestartHow int

	// enum {
	// 	SIGSTOP_IGNORED = 0,  /* Ignore SIGSTOP (once the parent is known).  */
	// 	SIGSTOP_ALLOWED,      /* Allow SIGSTOP (once the parent is known).   */
	// 	SIGSTOP_PENDING,      /* Block SIGSTOP until the parent is unknown.  */
	// } sigstop;
	Sigstop int

	// Specify the type of the final component during the initialization of a binding.  This variable is first defined in bind_path() then used in build_glue().
	GlueType int

	// Disable mixed-execution (native host) check.
	MixedMode bool

	// State of the seccomp acceleration for this tracee.
	// enum { DISABLED = 0, DISABLING = 1, ENABLED = 2 } seccomp;
	Seccomp int

	Regs unix.PtraceRegs

	// Ensure the sysexit stage is always hit under seccomp.
	SysexitPending bool

	// Path to the executable, à la /proc/self/exe.
	Exe, NewExe string

	// Runner command-line.
	Qemu []string

	// Path to glue between the guest rootfs and the host rootfs.
	Glue string

	/* For the mixed-mode, the guest LD_LIBRARY_PATH is saved
	 * during the "guest -> host" transition, in order to be
	 * restored during the "host -> guest" transition (only if the
	 * host LD_LIBRARY_PATH hasn't changed).  */
	HostLdsoPaths  string
	GuestLdsoPaths string
}

func (tracee *Tracee) GetTracee(pid int, create bool, nextVpid func() int) *Tracee {
	if tracee != nil && tracee.PID == pid {
		return tracee
	}
	for _, treacee := range tracee.Link {
		if treacee.PID == pid {
			return treacee
		}
	}
	if create && nextVpid != nil {
		newTracee := &Tracee{
			PID:    pid,
			Vpid:   nextVpid(),
			Link:   []*Tracee{},
			Parent: tracee,
		}
		tracee.Link = append(tracee.Link, newTracee)
		return newTracee
	}
	return nil
}

func (ptracee *Tracee) GetPtracee(pid int, onlyStopped, onlyWithPevent bool, waitOption int) *Tracee {
	for _, zombie := range ptracee.AsPtracer.Zombies {
		for _, ptracee := range zombie.Link {
			if pid != ptracee.PID && pid != -1 {
				continue
			}
			// #define EXPECTED_WAIT_CLONE(wait_options,tracee) ((((wait_options) & __WALL) != 0) || ((((wait_options) & __WCLONE) != 0) && (tracee)->clone) || ((((wait_options) & __WCLONE) == 0) && !(tracee)->clone))
			if !ptracee.Clone {
				continue
			}
			return ptracee
		}
	}

	for _, ptracee := range ptracee.Link {
		if ptracee.AsPtracee.Ptrace == nil || ptracee.PID != pid && pid != -1 {
			continue
		}
		// #define EXPECTED_WAIT_CLONE(wait_options,tracee) ((((wait_options) & __WALL) != 0) || ((((wait_options) & __WCLONE) != 0) && (tracee)->clone) || ((((wait_options) & __WCLONE) == 0) && !(tracee)->clone))
		if !ptracee.Clone {
			continue
		}

		if !onlyStopped {
			return ptracee
		}

		if ptracee.Running {
			continue
		}

		if ptracee.AsPtracee.Event4.Ptracer.Pending || !onlyWithPevent {
			return ptracee
		}

		if ptracee.PID == pid {
			return nil
		}
	}
	return nil
}

func (ptracee *Tracee) GetStoppedPtracee(pid int, onlyWithPevent bool, waitOptions int) *Tracee {
	return ptracee.GetPtracee(pid, true, onlyWithPevent, waitOptions)
}

func (ptracee *Tracee) HasPtracee(pid, waitOptions int) bool {
	return ptracee.GetPtracee(pid, false, false, waitOptions) != nil
}

func (tracee *Tracee) FreeTerminatedTracees() {
	for index, tracee := range tracee.Link {
		if tracee.Terminated {
			tracee.Link = append(tracee.Link[:index], tracee.Link[min(len(tracee.Link)-1, index+1):]...)
		}
	}
}

func (tracee *Tracee) TerminateTracee() {
	tracee.Terminated = true
	if tracee.KillallOnExit {
		unix.Kill(tracee.PID, unix.SIGKILL)
		for _, pid := range tracee.Link {
			unix.Kill(pid.PID, unix.SIGKILL)
		}
	}
}

func (parent *Tracee) NewChild(cloneFlags int) error {
	if err := parent.fetchRegs(); err == nil {
		// 	if (status >= 0 && get_sysnum(parent, CURRENT) == PR_clone)
		// 	clone_flags = peek_reg(parent, CURRENT, SYSARG_1);
		// else if (status >= 0 && get_sysnum(parent, CURRENT) == PR_clone3)
		// 	clone_flags = peek_word(parent, peek_reg(parent, CURRENT, SYSARG_1));
	}
	return nil
}
