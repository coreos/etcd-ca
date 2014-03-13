# Security

## File Permission

etcd-ca saves all data as files, and set different permission for them.

Certificates are all set to be 0444, which could be read by all users.

All other host files are all set to be 0440, which is manage by the user group.

All other CA files and program management files are set to be 0400.

Before getting files, it would also check the permission to prevent attacks from other users in the system. For example, 'evil' creates file ca.key with 0666 file perm, 'core', who treates itself as admin for etcd-ca, reads it and uses it as ca.key, which may cause the security problem of fake certificate and key.

## User Permission (In Progress)

etcd-ca remembers all info about user who inits it, and treats it as administer, while users in the same group are assistants.

Only administer could manage certificate authority, including signing for host certificate request.

Assistants and administer could manage host identities.
