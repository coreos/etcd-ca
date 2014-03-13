# etcd-ca

A simple certificate manager written in Go. Easy to use with limited capability.

[![Build Status](https://drone.io/github.com/coreos/etcd-ca/status.png)](https://drone.io/github.com/coreos/etcd-ca/latest)

## Common Uses

etcd-ca allows you to build your own certificate system:

1. Create certificate authority
2. Create, issue and export host certificates
3. Manage host identities
4. Deploy a Public Key Infrastructure

Primarly used for [coreos/etcd](https://github.com/coreos/etcd) SSL/TLS testing.

## Certificate architecture

etcd-ca inits a certificate authority, and issues certificates using the authority only. It indicates the length of authorization path is at most 2.

## Examples

### Create a new certificate authority:

```
$ ./etcd-ca init
Created ca/key
Created ca/crt
```

### Create a new host identity, including keypair and certificate request:

```
$ ./etcd-ca new-cert alice
Created alice/key
Created alice/csr
```

### Sign certificate request of host and generate the certificate:

```
$ ./etcd-ca sign alice
Created alice/crt from alice/csr signed by ca.key
```

### Export the certificate chain for host:

```
$ ./etcd-ca chain alice
----BEGIN CERTIFICATE-----
CA certificate body
-----END CERTIFICATE-----
----BEGIN CERTIFICATE-----
alice certificate body
-----END CERTIFICATE-----
```

### Package up the certificate and key of host:

```
$ ./etcd-ca export alice > alice.tar
```

### List the status of all certificates:

```
$ ./etcd-ca status
ca: WARN (60 days until expiration)
alice: OK (120 days until expiration)
bob: Unsigned
```

## Getting Started

### Building

You can build etcd-ca from source:

```
$ git clone https://github.com/coreos/etcd-ca
$ cd etcd-ca
$ ./build
```

This will generate a binary called `./bin/etcd-ca`

## Project Details

### Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details on submitting patches and contacting developers via IRC and mailing lists.

### License

fleet is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
