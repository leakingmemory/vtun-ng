%define name vtun
%define version 2.0
%define release 1
Name: %{name}
Version: %{version}
Release: %{release}
Copyright: GPL
Group: Networking/Tunnels
Url: http://vtun.netpedia.net
Source: http://vtun.netpedia.net/%{name}-%{version}.tar.gz
Summary: Virtual tunnel over TCP/IP networks.
Vendor: Maxim Krasnyansky <max_mk@yahoo.com>
Packager: Maxim Krasnyansky <max_mk@yahoo.com>
BuildRoot: /var/tmp/%{name}-%{version}-build
Obsoletes: vppp

%description
VTun provides the method for creating Virtual Tunnels over TCP/IP networks
and allows to shape, compress, encrypt traffic in that tunnels. 
Supported type of tunnels are: PPP, IP, Ethernet and most of other serial 
protocols and programs.

VTun is easily and highly configurable, it can be used for various network
task like VPN, Mobil IP, Shaped Internet access, IP address saving, etc.
It is completely user space implementation and does not require modification
to any kernel parts. 

You need SSLeay-devel and lzo-devel to build it.

%prep
%setup

%build
CFLAGS="$RPM_OPT_FLAGS"; ./configure 		   \
            --prefix=$RPM_BUILD_ROOT/usr 	   \
	    --sysconfdir=$RPM_BUILD_ROOT/etc 	   \
	    --localstatedir=$RPM_BUILD_ROOT/var	   \
            --with-crypto-headers=/usr/include/ssl \
            --with-lzo-headers=/usr/include/lzo

make CFG_FILE=/etc/vtund.conf PID_FILE=/var/run/vtund.pid STAT_DIR=/var/log/vtun

%install
install -d $RPM_BUILD_ROOT/usr/sbin
install -d $RPM_BUILD_ROOT/usr/man/man8
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT/var/log/vtun

make install

install scripts/vtund.rc.red_hat $RPM_BUILD_ROOT/etc/rc.d/init.d/vtund

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf ../%{name}-%{version}

%files
%defattr(644,root,root)
%doc ChangeLog Credits README README.Config README.Shaper FAQ
%doc TODO vtund.conf 
%attr(755,root,root) %config /etc/rc.d/init.d/vtund
%attr(600,root,root) %config /etc/vtund.conf
%attr(755,root,root) /usr/sbin/vtund
%attr(755,root,root) %dir /var/log/vtund
/usr/man/man8/vtund.8
/usr/man/man8/vtun.8

%changelog
* Tue Nov 23 1999 Dag Wieers <dag@mind.be> 
- Added Url and Obsoletes-headers
- Added changelog ;)
- Changed summary
