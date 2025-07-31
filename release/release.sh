#!/bin/sh

version=$1

autoconf
rm -f vtun-ng-$version.tar.gz
tar -czvf vtun-ng-$version.tar.gz packages src Cargo.lock Cargo.toml build.rs install.sh scripts ChangeLog Credits FAQ README README.OpenSSL README.Setup README.Shaper TODO vtunngd.8 vtunngd.conf vtunngd.conf.5 license.txt
rm -rf vtun-ng-$version
mkdir vtun-ng-$version
cd vtun-ng-$version
tar xzvf ../vtun-ng-$version.tar.gz
cd ..
rm -f vtun-ng-$version.tar.gz
tar -czvf vtun-ng-$version.tar.gz vtun-ng-$version
rm -rf vtun-ng-$version
