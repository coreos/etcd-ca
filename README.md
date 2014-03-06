## etcd-ca

A very simple CA manager written in Go. Primarly used for coreos/etcd SSL/TLS
testing.

[![Build Status](https://drone.io/github.com/coreos/etcd-ca/status.png)](https://drone.io/github.com/coreos/etcd-ca/latest)

### Examples

Create a new CA:

```
$ ./etcd-ca new cluster
Created ./cluster/ca.key
Created ./cluster/ca.crt
```

Create a new certificate:

```
$ ./etcd-ca cert new host1
Created ./cluster/host1.key
Created ./cluster/host1.csr
```

Sign the new certificate for host1 with the ca:

```
$ ./etcd-ca ca sign ./cluster host1
Created ./cluster/host1.crt from ./cluster/host1.csr signed by ./cluster/ca.key
```
