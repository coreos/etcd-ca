package depot

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

// Depot is in charge of data storage
type Depot interface {
	Put(name string, data []byte, perm os.FileMode) error
	Get(name string) ([]byte, error)
	Delete(name string)
}

// FileDepot is a implementation of Depot using file system
type FileDepot struct {
	// Absolute path of directory that holds all files
	Dir string
}

func New(dir string) (*FileDepot, error) {
	dirpath, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	//TODO(yichengq): check directory permission

	return &FileDepot{dirpath}, nil
}

func (d *FileDepot) path(name string) string {
	return filepath.Join(d.Dir, name)
}

func (d *FileDepot) Put(name string, data []byte, perm os.FileMode) error {
	if data == nil {
		return errors.New("data is nil")
	}

	if err := os.MkdirAll(d.Dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(d.path(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}

	if _, err := file.Write(data); err != nil {
		file.Close()
		os.Remove(d.path(name))
		return err
	}

	file.Close()
	return nil
}

func (d *FileDepot) Get(name string) ([]byte, error) {
	return ioutil.ReadFile(d.path(name))
}

func (d *FileDepot) Delete(name string) {
	os.Remove(d.path(name))
}
