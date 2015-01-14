#!/bin/bash
#
# This script is the example to generate cert-related files for etcd.

# location for temporary depot
depot=".depot"
# The passphrases for the keys are `asdf`.
passphrase="--passphrase asdf"
# hostname and ip
server1hostname="etcd1"
server2hostname="etcd2"
server3hostname="etcd3"
server1ip="127.0.0.1"
server2ip="127.0.0.1"
server3ip="127.0.0.1"

if [ $# -eq 0 ]; then
	# try to find it through $GOPATH
	IFS=':' read -a paths <<< "${GOPATH}"
	for path in ${paths[@]}; do
		if [ -f "${path}/bin/etcd-ca" ]; then
			ca="${path}/bin/etcd-ca --depot-path $depot"
			break
		fi
	done
	if [ "$ca" == "" ]; then echo "Failed finding etcd-ca binary"; exit 1; fi
else
	# treat the first argument as the path to etcd-ca binary
	ca="$1 --depot-path $depot"
fi

rm -rf $depot 2>/dev/null

# create ca
$ca init $passphrase
$ca export | tar xvf -

# create certificate for server
$ca new-cert $passphrase --ip $server1ip --domain $server1hostname server1
$ca sign $passphrase server1
$ca export --insecure $passphrase server1 | tar xvf -

$ca new-cert $passphrase --ip $server2ip --domain $server2hostname server2
$ca sign $passphrase server2
$ca export --insecure $passphrase server2 | tar xvf -

$ca new-cert $passphrase --ip $server3ip --domain $server3hostname server3
$ca sign $passphrase server3
$ca export --insecure $passphrase server3 | tar xvf -

# create certificate for client
$ca new-cert $passphrase client
$ca sign $passphrase client
$ca export --insecure $passphrase client | tar xvf -
