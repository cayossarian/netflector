#!/bin/sh
# Copy the working tree's port into the VM's ports tree and register it in
# net/Makefile's SUBDIR list: the list entry is a deliverable of the ports-tree
# submission, and portlint checks it.
set -eu

# scp -r nests into an existing directory; see ci/freebsd-port-package.sh.
ci/freebsd-vm.sh run 'rm -rf /usr/ports/net/netflector'
ci/freebsd-vm.sh push dist/freebsd/net/netflector /usr/ports/net/netflector
# The port's account: 396, the slot UIDs marks free, until the tree carries it.
ci/freebsd-vm.sh run 'cd /usr/ports && for f in UIDs GIDs; do grep -q "^netflector:" $f && continue; case $f in UIDs) line="netflector:*:396:396::0:0:netflector daemon:/nonexistent:/usr/sbin/nologin" ;; GIDs) line="netflector:*:396:" ;; esac; awk -F: -v l="$line" "!ins && /^[^#]/ && \$3 > 396 { print l; ins = 1 } { print } END { if (!ins) print l }" $f > $f.new && mv $f.new $f; done && grep -n "^netflector:" UIDs GIDs'
ci/freebsd-vm.sh run 'cd /usr/ports/net && awk "/^ *SUBDIR \+= / && !ins && \$3 > \"netflector\" { print \"    SUBDIR += netflector\"; ins = 1 } { print } END { if (!ins) print \"    SUBDIR += netflector\" }" Makefile > Makefile.new && mv Makefile.new Makefile && grep -n "SUBDIR += netflector" Makefile'
