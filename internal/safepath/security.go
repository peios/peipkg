package safepath

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/files"
	"github.com/peios/libp-go/sd"
	"golang.org/x/sys/unix"
)

// SetDirectoryDescriptors configures explicit package boundaries before any
// planning or extraction creates parents. Unlisted existing directories retain
// their descriptors; there is deliberately no recursive ACL reset.
func (r *Root) SetDirectoryDescriptors(descriptors map[string][]byte, stamp func(string, []byte) error) {
	r.directorySD = descriptors
	r.stampSD = stamp
	r.appliedSD = make(map[string]bool)
}

func (r *Root) mkdirAt(parent int, name, rel string, perm os.FileMode) error {
	descriptor := r.directorySD[rel]
	if len(descriptor) > 0 {
		f, _, err := files.OpenAt(parent, name, files.OpenOptions{
			Access:      files.ListDirectory | files.Traverse,
			Disposition: files.DispCreate, Directory: true, SecurityDescriptor: descriptor,
		})
		if err == nil {
			r.appliedSD[rel] = true
			return f.Close()
		}
		if !errors.Is(err, errno.ENOSYS) {
			return err
		}
	}
	return unix.Mkdirat(parent, name, uint32(perm.Perm()))
}

func (r *Root) applyDirectorySD(fd int, rel string) error {
	descriptor := r.directorySD[rel]
	if len(descriptor) == 0 || r.appliedSD[rel] {
		return nil
	}
	info := sd.InfoOwner | sd.InfoGroup | sd.InfoDACL
	// Include a SACL only when the manifest supplies one. Updating a DACL
	// alone must not request SeSecurityPrivilege through an absent SACL.
	if len(descriptor) > 2 && descriptor[2]&0x10 != 0 {
		info |= sd.InfoSACL
	}
	err := sd.SetSD(sd.FD(fd), info, descriptor)
	if errors.Is(err, errno.ENOSYS) {
		err = r.stampSD(path.Join(r.path, rel), descriptor)
	}
	if err == nil {
		r.appliedSD[rel] = true
	}
	return err
}

// CreateWithSD uses the native atomic creator descriptor on Peios. Off Peios,
// the image builder stamps (or records) the descriptor before copying bytes.
// Only ENOSYS permits that fallback: a rejected descriptor must fail closed.
func (d *Dir) CreateWithSD(name string, perm os.FileMode, descriptor []byte, stamp func(string, []byte) error) (*os.File, error) {
	if len(descriptor) == 0 {
		return d.Create(name, perm)
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	handle, _, err := files.OpenAt(d.fd, name, files.OpenOptions{
		Access:      files.WriteData | files.WriteAttributes | files.WriteDAC | files.Synchronize,
		Disposition: files.DispCreate, SecurityDescriptor: descriptor,
	})
	if err == nil {
		fd, dupErr := unix.FcntlInt(uintptr(handle.FD()), unix.F_DUPFD_CLOEXEC, 0)
		handle.Close()
		if dupErr != nil {
			return nil, dupErr
		}
		f := os.NewFile(uintptr(fd), path.Join(d.abs, name))
		if err := f.Chmod(perm); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}
	if !errors.Is(err, errno.ENOSYS) {
		return nil, fmt.Errorf("creating %s with descriptor: %w", path.Join(d.abs, name), err)
	}
	f, err := d.Create(name, perm)
	if err != nil {
		return nil, err
	}
	if err := stamp(f.Name(), descriptor); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
