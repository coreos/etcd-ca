# Template

## Certificate Authority

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=USA, O=etcd-ca, OU=CA
        Validity
            Not Before: Mar 13 06:09:55 2014 GMT
            Not After : Mar 13 06:09:55 2024 GMT
        Subject: C=USA, O=etcd-ca, OU=CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: [ ... ]
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier:
                [ ... ]
            X509v3 Authority Key Identifier:
                keyid:[ ... ]

    Signature Algorithm: sha1WithRSAEncryption
        [ ... ]
```

## Certificate signing request

```
Certificate Request:
    Data:
        Version: 0 (0x0)
        Subject: C=USA, O=etcd-ca, OU=alice, CN=127.0.0.1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: [ ... ]
        Attributes:
            [ ... ]
    Signature Algorithm: sha1WithRSAEncryption
        [ ... ]
```

## Certificate for host

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 2 (0x2)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: C=USA, O=etcd-ca, OU=CA
        Validity
            Not Before: Mar 13 06:10:27 2014 GMT
            Not After : Mar 13 06:10:27 2024 GMT
        Subject: C=USA, O=etcd-ca, OU=alice, CN=127.0.0.1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: [ ... ]
        X509v3 extensions:
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier:
                [ ... ]
            X509v3 Authority Key Identifier:
                keyid:[ ... ]

            X509v3 Subject Alternative Name:
                IP Address:127.0.0.1
    Signature Algorithm: sha1WithRSAEncryption
        [ ... ]
```
