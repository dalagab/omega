//go:build !windows

package download

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
