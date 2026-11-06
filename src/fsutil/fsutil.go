// Package fsutil opens files that hold captured traffic or HEP data safely:
// owner-only permissions and no following of symlinks planted at the path.
package fsutil

import "os"

const (
	// FileMode is used for pcap dumps and the HEP buffer: they contain
	// captured signalling (SIP auth digests, phone numbers).
	FileMode os.FileMode = 0o600
	// DirMode is used for directories created for those files.
	DirMode os.FileMode = 0o750
)

// Create creates or truncates path for writing with FileMode. On Unix it
// refuses to follow a symlink at path, so a link planted in a shared
// directory cannot redirect a root-owned write.
func Create(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|noFollow, FileMode)
}

// Append opens path for appending with FileMode, creating it if needed,
// without following a symlink at path (Unix).
func Append(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|noFollow, FileMode)
}

// WriteFile writes data to path like os.WriteFile, with FileMode and no
// symlink following (Unix).
func WriteFile(path string, data []byte) error {
	f, err := Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
