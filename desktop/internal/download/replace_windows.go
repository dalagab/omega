//go:build windows

package download

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	moveFileExProc = kernel32.NewProc("MoveFileExW")
)

func replaceFile(source, destination string) error {
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	ok, _, callErr := moveFileExProc.Call(
		uintptr(unsafe.Pointer(src)),
		uintptr(unsafe.Pointer(dst)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if ok == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return fmt.Errorf("MoveFileExW failed")
	}
	return nil
}
