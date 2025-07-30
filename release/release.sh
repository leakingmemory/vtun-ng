#!/bin/sh

version=$1

autoconf
rm -f vtun-ng-$version.tar.gz
tar -czvf vtun-ng-$version.tar.gz packages rust/linkfd/src rust/linkfd/Cargo.lock rust/linkfd/Cargo.toml scripts *.m4 lib.c main.c *.h ChangeLog config.guess *.in config.sub configure Credits FAQ install-sh README README.OpenSSL README.Setup README.Shaper TODO vtun.drivers vtunngd.8 vtunngd.conf vtunngd.conf.5 license.txt
rm -rf vtun-ng-$version
mkdir vtun-ng-$version
cd vtun-ng-$version
tar xzvf ../vtun-ng-$version.tar.gz
cd ..
rm -f vtun-ng-$version.tar.gz
tar -czvf vtun-ng-$version.tar.gz vtun-ng-$version
rm -rf vtun-ng-$version
