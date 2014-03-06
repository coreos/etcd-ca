## etcd-ca

A very simple CA manager written in Go. Primarly used for coreos/etcd SSL/TLS
testing.

[![Build Status](https://drone.io/github.com/coreos/etcd-ca/status.png)](https://drone.io/github.com/coreos/etcd-ca/latest)

### Examples

Create a new CA:

```
$ ./etcd-ca init
Created ca/key
Created ca/crt
```

Create a new certificate:

```
$ ./etcd-ca new-cert host1
Created host1/key
Created host1/csr
```

Sign the new certificate for host1 with the ca:

```
$ ./etcd-ca sign host1
Created host1/crt from host1/csr signed by ca.key
```

Export the certificate chain for host1. With no args it exports this CA's
certificate.

```
$ ./etcd-ca chain host1
----BEGIN CERTIFICATE-----
CA certificate body
-----END CERTIFICATE-----
----BEGIN CERTIFICATE-----
host1 certificate body
-----END CERTIFICATE-----
```

Package up a certificate and key for export to a server:

```
$ ./etcd-ca export host1 > host1.tar
```

Get the status of all certificates:

```
$ ./etcd-ca status
ca: WARN (60 days until expiration)
host1: OK (120 days until expiration)
host2: Unsigned
```
