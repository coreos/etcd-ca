# Work with etcd

## Genereate certificates

Use etcd-ca to init ca and host:

```
./etcd-ca init --passphrase=""
./etcd-ca new-cert --passphrase="" server
./etcd-ca sign --passphrase="" server
./etcd-ca new-cert --passphrase="" server2
./etcd-ca sign --passphrase="" server2
```

Export files that are used for etcd later:

```
./etcd-ca export --passphrase="" --insecure | tar xvf -
./etcd-ca export --passphrase="" --insecure server | tar xvf -
./etcd-ca chain server > server-chain.pem
./etcd-ca export --passphrase="" --insecure server2 | tar xvf -
```

## Transport Security with HTTPS (etcd Server)

Configure etcd to use this keypair:

```
./etcd -f -name machine0 -data-dir machine0 -cert-file=server.crt -key-file=server.key.insecure
```

Connect to etcd using HTTPS:

```
curl --cacert server-chain.pem https://127.0.0.1:4001/v2/keys/foo -XPUT -d value=bar -v
```

The value should be set successfully.

### Special case for OSX 10.9+ Users

curl 7.30.0 on OSX 10.9+ doesn't understand certificates passed in on the command line. Instead you must import the dummy ca.crt directly into the keychain or add the -k flag to curl to ignore errors. If you want to test without the -k flag run `open ca.crt` and follow the prompts. Please remove this certificate after you are done testing!

## Authentication with HTTPS Client Certificates (etcd Server)

Configure etcd to verify certificate using CA also:

```
./etcd -f -name machine0 -data-dir machine0 -ca-file=ca.crt -cert-file=server.crt -key-file=server.key.insecure
```

The same request should be rejected this time:

```
curl --cacert server-chain.pem https://127.0.0.1:4001/v2/keys/foo -XPUT -d value=bar -v
```

And curl will tell you that:

```
curl: (35) error:14094412:SSL routines:SSL3_READ_BYTES:sslv3 alert bad certificate
```

Give the CA signed cert to the server:

```
curl --key server.key.insecure --cert server.crt --cacert server-chain.pem -L https://127.0.0.1:4001/v2/keys/foo -XPUT -d value=bar -v
```

The value should be set successfully.

### Hint

curl 7.33.0+ should be used to support TLS v1.2.

## Authentication with HTTPS Client Certificates (etcd Peer Server)

Configure etcd to verify certificate between connection with other peers servers:

```
./etcd -f -name machine0 -data-dir machine0 -peer-ca-file=ca.crt -peer-cert-file=server.crt -peer-key-file=server.key.insecure
./etcd -f -peer-addr 127.0.0.1:7002 -addr 127.0.0.1:4002 -peers 127.0.0.1:7001 -data-dir machine1 -name machine1 -peer-ca-file=ca.crt -peer-cert-file=server2.crt -peer-key-file=server2.key.insecure
```

Set value to see the cluster works:

```
curl http://127.0.0.1:4001/v2/keys/foo -XPUT -d value=bar -v
```

## Reference

More details could be checked in [etcd/Documentation/security](https://github.com/coreos/etcd/blob/master/Documentation/security.md) and [script shell to generate ca](https://github.com/coreos/etcd/blob/master/fixtures/ca/generate_testing_certs.sh)
