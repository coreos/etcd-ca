package depot

import (
	"errors"
	"github.com/coreos/go-etcd/etcd"
	"strings"
)

// EtcdDepot is a implementation of Depot using etcd
type EtcdDepot struct {
	url    string
	keyPre string
}

func NewEtcdDepot(url string) (*EtcdDepot, error) {
	if url == DefaultFileDepotDir {
		url = "http://127.0.0.1:4001"
	}
	keyPre := "foo/"
	return &EtcdDepot{url, keyPre}, nil
}

func (d *EtcdDepot) Put(tag *Tag, data []byte) error {
	if data == nil {
		return errors.New("data is nil")
	}
	etc := etcd.NewClient([]string{d.url})
	_, err := etc.Set(d.keyPre+tag.name, string(data), 0)
	return err
}

func (d *EtcdDepot) Check(tag *Tag) bool {
	etc := etcd.NewClient([]string{d.url})
	_, err := etc.Get(d.keyPre+tag.name, false, false)
	if err != nil {
		return false
	}
	return true
}

func (d *EtcdDepot) Get(tag *Tag) ([]byte, error) {
	etc := etcd.NewClient([]string{d.url})
	result, err := etc.Get(d.keyPre+tag.name, false, false)
	if err != nil {
		return nil, err
	}
	return []byte(result.Node.Value), nil
}

func (d *EtcdDepot) Delete(tag *Tag) error {
	etc := etcd.NewClient([]string{d.url})
	_, err := etc.Delete(d.keyPre+tag.name, false)
	if err != nil {
		return err
	}
	return nil
}

func (d *EtcdDepot) List() []*Tag {
	tags := make([]*Tag, 0)
	etc := etcd.NewClient([]string{d.url})
	result, err := etc.Get(d.keyPre, false, false)
	if err != nil {
		return tags
	}
	for _, n := range result.Node.Nodes {
		n := strings.TrimPrefix(n.Key, d.keyPre)
		tags = append(tags, &Tag{n, 0666})
	}
	return tags
}

func (d *EtcdDepot) GetFile(tag *Tag) (*File, error) {
	b, err := d.Get(tag)
	return &File{nil, b}, err
}
