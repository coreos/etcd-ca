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

etcd-ca uses 127.0.0.1 for IP SAN in default. If etcd has peer address $etcd_ip other than 127.0.0.1, run `./etcd-ca new-cert --ip $etcd_ip alice` instead.

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

Because etcd takes unencrypted key for `-key-file` and `-peer-key-file`, you should use `./etcd-ca export --insecure alice > alice.tar` to export private key.

### List the status of all certificates:

```
$ ./etcd-ca status
ca: WARN (60 days until expiration)
alice: OK (120 days until expiration)
bob: Unsigned
```

## Getting Started

### Building

etcd-ca must be built with Go 1.2+. You can build etcd-ca from source:

```
$ git clone https://github.com/coreos/etcd-ca
$ cd etcd-ca
$ ./build
```

This will generate a binary called `./bin/etcd-ca`

### EtcD storage

By default, etcd-ca stores secrets on your local filesystem.

To store secrets in etcd, use the `--depot etcd` flag.  When this flag is enabled, the --depot-path flag is used to specify the etcd URL.

## Project Details

### Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details on submitting patches and contacting developers via IRC and mailing lists.

### License

etcd-ca is under the Apache 2.0 license. See the [LICENSE](LICENSE) file for details.
