//go:build windows

package processutil

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// HideWindow starts console-subsystem helpers without allocating a new console
// window. Their stdout/stderr can still be redirected to the DeltaScope log or
// an explicit developer console owned by the parent process.
func HideWindow(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	attr := cmd.SysProcAttr
	if attr == nil {
		attr = &syscall.SysProcAttr{}
	}
	attr.HideWindow = true
	attr.CreationFlags |= createNoWindow
	cmd.SysProcAttr = attr
}
