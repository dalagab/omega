//go:build !windows

package processutil

import "os/exec"

// HideWindow is a no-op away from Windows. Unix child processes do not create
// separate console windows merely because DeltaScope is launched graphically.
func HideWindow(cmd *exec.Cmd) {
	_ = cmd
}
