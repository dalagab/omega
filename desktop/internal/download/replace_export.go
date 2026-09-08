package download

// ReplaceFile atomically replaces destination with source using the same
// platform-specific write-through primitive used by the downloader.
func ReplaceFile(source, destination string) error {
	return replaceFile(source, destination)
}
