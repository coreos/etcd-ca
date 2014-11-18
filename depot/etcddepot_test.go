package depot

import (
	"bytes"
	"os"
	"testing"
)

const (
	etcdata = "It is a trap only!"
	etcdir  = ".etcd-ca"
)

var (
	etctag       = &Tag{"host.pem", 0600}
	etctag2      = &Tag{"host2.pem", 0600}
	etcwrongTag  = &Tag{"host.pem", 0666}
	etcwrongTag2 = &Tag{"host.pem2", 0600}
)

func etcgetDepot(t *testing.T) *EtcdDepot {
	d, err := NewEtcdDepot(etcdir)
	if err != nil {
		t.Fatal("Failed init Depot:", err)
	}
	return d
}

// TestEtcdDepotCRUD tests to create, update and delete data
func TestEtcdDepotCRUD(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(etctag, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	dataRead, err := d.Get(etctag)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}
	if bytes.Compare(dataRead, []byte(etcdata)) != 0 {
		t.Fatal("Failed getting the previous data")
	}

	if err = d.Put(etctag, []byte(etcdata)); err == nil || !os.IsExist(err) {
		t.Fatal("Expect not to put file into Depot:", err)
	}

	d.Delete(etctag)

	if d.Check(etctag) {
		t.Fatal("Failed deleting file from Depot:", err)
	}
}

func TestEtcdDepotPutNil(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(etctag, nil); err == nil {
		t.Fatal("Expect not to put nil into Depot:", err)
	}

	if err := d.Put(etctag, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	d.Delete(etctag)
}

func TestEtcdDepotCheckFailure(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(etctag, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if d.Check(etcwrongTag) {
		t.Fatal("Expect not to checking out file with insufficient permission")
	}

	if d.Check(etcwrongTag2) {
		t.Fatal("Expect not to checking out file with nonexist name")
	}

	d.Delete(etctag)
}

func TestEtcdDepotGetFailure(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(etctag, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	if _, err := d.Get(etcwrongTag); err == nil {
		t.Fatal("Expect not to checking out file with insufficient permission")
	}

	if _, err := d.Get(etcwrongTag2); err == nil {
		t.Fatal("Expect not to checking out file with nonexist name")
	}

	d.Delete(etctag)
}

func TestEtcdDepotList(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(etctag, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}
	if err := d.Put(etctag2, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	tags := d.List()
	if len(tags) != 2 {
		t.Fatal("Expect to list 2 instead of", len(tags))
	}
	if tags[0].name != etctag.name || tags[1].name != etctag2.name {
		t.Fatal("Failed getting file tags back")
	}
}

func TestEtcdDepotGetFile(t *testing.T) {
	d := getDepot(t)

	if err := d.Put(etctag, []byte(etcdata)); err != nil {
		t.Fatal("Failed putting file into Depot:", err)
	}

	file, err := d.GetFile(etctag)
	if err != nil {
		t.Fatal("Failed getting file from Depot:", err)
	}
	if bytes.Compare(file.Data, []byte(etcdata)) != 0 {
		t.Fatal("Failed getting the previous data")
	}

	if file.Info.Mode() != etctag.perm {
		t.Fatal("Failed setting permission")
	}
}
