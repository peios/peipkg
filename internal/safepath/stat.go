package safepath

import (
	"io/fs"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// statInfo adapts a raw stat buffer to fs.FileInfo. Only the fields
// peipkg reads are meaningful; Sys returns the buffer for anything else.
type statInfo struct {
	name string
	st   unix.Stat_t
}

func (s *statInfo) Name() string { return s.name }
func (s *statInfo) Size() int64  { return s.st.Size }
func (s *statInfo) IsDir() bool  { return s.Mode().IsDir() }
func (s *statInfo) ModTime() time.Time {
	return time.Unix(s.st.Mtim.Sec, s.st.Mtim.Nsec)
}
func (s *statInfo) Sys() any { return &s.st }

func (s *statInfo) Mode() fs.FileMode {
	mode := fs.FileMode(s.st.Mode & 0o777)
	switch s.st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= fs.ModeSocket
	case unix.S_IFCHR:
		mode |= fs.ModeCharDevice | fs.ModeDevice
	case unix.S_IFBLK:
		mode |= fs.ModeDevice
	}
	if s.st.Mode&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if s.st.Mode&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if s.st.Mode&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

var _ os.FileInfo = (*statInfo)(nil)
