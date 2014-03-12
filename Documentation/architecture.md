# Architecture

## Moving Parts

### Depot

The Depot is the storage manager. All files are stored in the Depot: certificates, keys, certificate requests and etc.

**NOTE:**The backing store is the file system. Users could fetch all certifications and keys without the help of the program.

**NOTE:**File system permissions are used to secure certifications and keys. Data is categorized into different security level, and each level has its own specific permission.

### Cmd

The cmd package is to handle commands according to its meaning.

## Object Model

### Certificate

The Certificate represents certificate issued.

It could be CA certificate, or certificate for host.

### Key

The Key represents key generated, which consists of private key and public key.

It is used to sign and verify certificates.

### Certificate signing request

The Certificate signing request is the request that sends to CA for signing to generate certificate for host.

### Certificate Authority Info

The Certificate Authority Info is the extra information needed for CA.

Serial number, the only member of Info, represents number that has been used for signing so far. It is recorded to ensure that serial number issued for each certificate is unique.
