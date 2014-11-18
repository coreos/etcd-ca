package depot

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	DefaultFileDepotDir = ".etcd-ca"
)

// FileDepot is a implementation of Depot using file system
type FileDepot struct {
	// Absolute path of directory that holds all files
	dirPath string
}

func NewFileDepot(dir string) (*FileDepot, error) {
	dirpath, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	//TODO(yichengq): check directory permission

	return &FileDepot{dirpath}, nil
}

func (d *FileDepot) path(name string) string {
	return filepath.Join(d.dirPath, name)
}

func (d *FileDepot) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}

	if err := os.MkdirAll(d.dirPath, 0755); err != nil {
		return err
	}

	name := d.path(tag.name)
	perm := tag.perm

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(name)
		return err
	}

	file.Close()
	return nil
}

func (d *FileDepot) Check(tag *Tag) bool {
	name := d.path(tag.name)
	if fi, err := os.Stat(name); err == nil && ^fi.Mode()&tag.perm == 0 {
		return true
	}
	return false
}

func (d *FileDepot) check(tag *Tag) error {
	name := d.path(tag.name)
	fi, err := os.Stat(name)
	if err != nil {
		return err
	}
	if ^fi.Mode()&tag.perm != 0 {
		return errors.New("permission denied")
	}
	return nil
}

func (d *FileDepot) Get(tag *Tag) ([]byte, error) {
	if err := d.check(tag); err != nil {
		return nil, err
	}
	return ioutil.ReadFile(d.path(tag.name))
}

func (d *FileDepot) Delete(tag *Tag) error {
	return os.Remove(d.path(tag.name))
}

func (d *FileDepot) List() []*Tag {
	tags := make([]*Tag, 0)

	filepath.Walk(d.dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(d.dirPath, path)
		if err != nil {
			return nil
		}
		if rel != info.Name() {
			return nil
		}
		tags = append(tags, &Tag{info.Name(), info.Mode()})
		return nil
	})

	return tags
}

func (d *FileDepot) GetFile(tag *Tag) (*File, error) {
	if err := d.check(tag); err != nil {
		return nil, err
	}
	fi, err := os.Stat(d.path(tag.name))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(d.path(tag.name))
	return &File{fi, b}, err
}
