//go:build windows

package process

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000
	processTerminate                  = 0x0001
	processSetQuota                   = 0x0100
	createNewProcessGroup             = 0x00000200
)

var (
	modKernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW        = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob      = modKernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject      = modKernel32.NewProc("TerminateJobObject")
)

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type windowsHandle struct {
	cmd       *exec.Cmd
	jobHandle syscall.Handle
	mu        sync.Mutex
	closed    bool
}

// Start 在 Windows 上启动受控进程并将其挂载到独立 Job Object，确保取消时彻底终止整个进程树。
func Start(spec Spec) (Handle, error) {
	cmd, err := BuildCommand(spec)
	if err != nil {
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup,
	}

	job, err := createKillOnCloseJob()
	if err != nil {
		return nil, fmt.Errorf("创建 Windows Job Object 失败: %w", err)
	}

	if err := cmd.Start(); err != nil {
		_ = syscall.CloseHandle(job)
		return nil, fmt.Errorf("启动进程失败: %w", err)
	}

	// 将已启动的进程绑定到 Job Object；即使绑定失败也回退到 PID 强杀而不影响任务清理
	if pHandle, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(cmd.Process.Pid)); err == nil {
		r1, _, _ := procAssignProcessToJob.Call(uintptr(job), uintptr(pHandle))
		_ = syscall.CloseHandle(pHandle)
		if r1 == 0 {
			_ = syscall.CloseHandle(job)
			job = 0
		}
	} else {
		_ = syscall.CloseHandle(job)
		job = 0
	}

	return &windowsHandle{
		cmd:       cmd,
		jobHandle: job,
	}, nil
}

func (h *windowsHandle) PID() int {
	if h.cmd == nil || h.cmd.Process == nil {
		return 0
	}
	return h.cmd.Process.Pid
}

func (h *windowsHandle) Wait() (int, error) {
	err := h.cmd.Wait()
	h.closeJob()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), err
	}
	return -1, err
}

func (h *windowsHandle) KillTree() error {
	h.mu.Lock()
	job := h.jobHandle
	h.mu.Unlock()

	if job != 0 {
		r1, _, callErr := procTerminateJobObject.Call(uintptr(job), 1)
		h.closeJob()
		if r1 != 0 {
			return nil
		}
		if h.cmd != nil && h.cmd.Process != nil {
			_ = h.cmd.Process.Kill()
		}
		return callErr
	}

	if h.cmd != nil && h.cmd.Process != nil {
		return h.cmd.Process.Kill()
	}
	return nil
}

func (h *windowsHandle) closeJob() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed && h.jobHandle != 0 {
		_ = syscall.CloseHandle(h.jobHandle)
		h.jobHandle = 0
		h.closed = true
	}
}

func createKillOnCloseJob() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, err
	}
	job := syscall.Handle(r1)

	var info jobObjectExtendedLimitInfo
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose

	r2, _, setErr := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r2 == 0 {
		_ = syscall.CloseHandle(job)
		return 0, setErr
	}
	return job, nil
}
