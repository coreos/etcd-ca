package depot

import (
	"bytes"
	"os"
	"testing"
)

const (
	name = "host.pem"
	data = "It is a trap only!"
	dir = ".etcd-ca"
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

	if err := d.Put(name, []byte(data), 0666); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	dataRead, err := d.Get(name)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}

	if bytes.Compare(dataRead, []byte(data)) != 0 {
		t.Fatal("Failed getting the previous data")
	}

	if err = d.Put(name, []byte(data), 0666); err == nil || !os.IsExist(err) {
		t.Fatal("Expect not to put file into Depot:", err)
	}

	d.Delete(name)

	if _, err = d.Get(name); err == nil || !os.IsNotExist(err) {
		t.Fatal("Failed deleting file from Depot:", err)
	}
}

func TestDepotPutNil(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(name, nil, 0666); err == nil {
		t.Fatal("Expect not to put nil into Depot:", err)
	}

	if err := d.Put(name, []byte(data), 0666); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	d.Delete(name)
}
