#!/bin/sh

version=$1

autoconf
rm -f vtun-ng-$version.tar.gz
tar -czvf vtun-ng-$version.tar.gz freebsd generic linux openbsd packages rust/linkfd/src rust/linkfd/Cargo.lock rust/linkfd/Cargo.toml scripts svr4 *.m4 auth.c client.c lfd_encrypt.c lfd_legacy_encrypt.c lfd_lzo.c lfd_shaper.c lfd_zlib.c lib.c linkfd.c llist.c lock.c main.c netlib.c server.c tunnel.c *.h *.l *.y ChangeLog config.guess *.in config.sub configure Credits FAQ install-sh README README.LZO README.OpenSSL README.Setup README.Shaper TODO vtun.drivers vtunngd.8 vtunngd.conf vtunngd.conf.5
rm -rf vtun-ng-$version
mkdir vtun-ng-$version
cd vtun-ng-$version
tar xzvf ../vtun-ng-$version.tar.gz
cd ..
rm -f vtun-ng-$version.tar.gz
tar -czvf vtun-ng-$version.tar.gz vtun-ng-$version
rm -rf vtun-ng-$version
