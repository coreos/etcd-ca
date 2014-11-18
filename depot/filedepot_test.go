package depot

import (
	"bytes"
	"os"
	"testing"
)

const (
	data = "It is a trap only!"
	dir  = ".etcd-ca-test"
)

var (
	tag       = &Tag{"host.pem", 0600}
	tag2      = &Tag{"host2.pem", 0600}
	wrongTag  = &Tag{"host.pem", 0666}
	wrongTag2 = &Tag{"host.pem2", 0600}
)

func getDepot(t *testing.T) *FileDepot {
	os.RemoveAll(dir)

	d, err := NewFileDepot(dir)
	if err != nil {
		t.Fatal("Failed init Depot:", err)
	}
	return d
}

// TestDepotCRUD tests to create, update and delete data
func TestDepotCRUD(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	dataRead, err := d.Get(tag)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}
	if bytes.Compare(dataRead, []byte(data)) != 0 {
		t.Fatal("Failed getting the previous data")
	}

	if err = d.Put(tag, []byte(data)); err == nil || !os.IsExist(err) {
		t.Fatal("Expect not to put file into Depot:", err)
	}

	d.Delete(tag)

	if d.Check(tag) {
		t.Fatal("Failed deleting file from Depot:", err)
	}
}

func TestDepotPutNil(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, nil); err == nil {
		t.Fatal("Expect not to put nil into Depot:", err)
	}

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	d.Delete(tag)
}

func TestDepotCheckFailure(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if d.Check(wrongTag) {
		t.Fatal("Expect not to checking out file with insufficient permission")
	}

	if d.Check(wrongTag2) {
		t.Fatal("Expect not to checking out file with nonexist name")
	}

	d.Delete(tag)
}

func TestDepotGetFailure(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if _, err := d.Get(wrongTag); err == nil {
		t.Fatal("Expect not to checking out file with insufficient permission")
	}

	if _, err := d.Get(wrongTag2); err == nil {
		t.Fatal("Expect not to checking out file with nonexist name")
	}

	d.Delete(tag)
}

func TestDepotList(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}
	if err := d.Put(tag2, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	tags := d.List()
	if len(tags) != 2 {
		t.Fatal("Expect to list 2 instead of", len(tags))
	}
	if tags[0].name != tag.name || tags[1].name != tag2.name {
		t.Fatal("Failed getting file tags back")
	}
}

func TestDepotGetFile(t *testing.T) {
	d := getDepot(t)
	defer os.RemoveAll(dir)

	if err := d.Put(tag, []byte(data)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	file, err := d.GetFile(tag)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}
	if bytes.Compare(file.Data, []byte(data)) != 0 {
		t.Fatal("Failed getting the previous data")
	}

	if file.Info.Mode() != tag.perm {
		t.Fatal("Failed setting permission")
	}
}
