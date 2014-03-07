# Architecture

## Moving Parts

### Depot

The Depot is the storage manager. All certifications and keys are stored in the Depot: CA, host, CSR, etc.

**NOTE:**The backing store is the file system. Users could fetch all certifications and keys without the help of the program.

**NOTE:**File system permissions are used to secure certifications and keys. Data is categorized into different security level, and each level has its own specific permission.

### CertAuthority

The CertAuthority is Certification Authority (CA).

It generates new key and certification for CA is no one exists.

It signs CSRs.

### HostCertManager

The HostCertManager is responsible for managing host certification.

It creates new certification for certain host.

It takes the signed CSRs into management.

### PermMonitor

The PermMonitor acts as monitor of all permission stuffs.

It checks the permission of user to operate on moving parts.

It gives out the file permission for generated files.

## Common Parts

### CLI

CLI is command line interface.
