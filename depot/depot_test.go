package depot

import (
	"bytes"
	"os"
	"testing"
)

const (
	data = "It is a trap only!"
	dir = ".etcd-ca"
)

var (
	tag = &Tag{"host.pem", 0600}
	wrongTag = &Tag{"host.pem", 0666}
	wrongTag2 = &Tag{"host.pem2", 0600}
)

func getDepot(t *testing.T) Depot {
	os.RemoveAll(dir)

	d, err := New(dir)
	if err != nil {
		t.Fatal("Failed init Depot:", err)
	}
	return d
}

// TestDepotCRUD tests to create, update and delete data
func TestDepotCRUD(t *testing.T) {
	d := getDepot(t)

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
