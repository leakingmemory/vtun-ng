%define name	vtun
%define version	2.3
%define release	1
%define prefix	/usr

# By default, builds without socks-support.
# To build with socks-support, issue:
#   rpm --define "USE_SOCKS yes" ...

Name: %{name}
Version: %{version}
Release: %{release}
Copyright: GPL
Group: Networking/Tunnels
Url: http://vtun.sourceforge.net/
Source: http://vtun.sourceforge.net/%{name}-%{version}.tar.gz
Summary: Virtual tunnel over TCP/IP networks.
Vendor: Maxim Krasnyansky <max_mk@yahoo.com>
Packager: Dag Wieers <dag@mind.be>
BuildRoot: /var/tmp/%{name}-%{version}-build
Obsoletes: vppp
Prefix: %{prefix}

%description
VTun provides the method for creating Virtual Tunnels over TCP/IP networks
and allows to shape, compress, encrypt traffic in that tunnels. 
Supported type of tunnels are: PPP, IP, Ethernet and most of other serial 
protocols and programs.

VTun is easily and highly configurable, it can be used for various network
tasks like VPN, Mobil IP, Shaped Internet access, IP address saving, etc.
It is completely user space implementation and does not require modification
to any kernel parts. 

This package is build with%{!?USE_SOCKS:out} SOCKS-support.

%prep
%setup -n %{name}-%{version}

%build
%configure					   \
            --prefix=$RPM_BUILD_ROOT%{prefix} 	   \
	    --sysconfdir=$RPM_BUILD_ROOT/etc 	   \
	    --localstatedir=$RPM_BUILD_ROOT/var	   \
            --enable-lzo                           \
%{?USE_SOCKS: --enable-socks}

make CFG_FILE=/etc/vtund.conf PID_FILE=/var/run/vtund.pid  \
     STAT_DIR=/var/log/vtund LOCK_DIR=/var/lock/vtund

%install
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT%{prefix}/sbin
install -d $RPM_BUILD_ROOT%{prefix}/man/man8
install -d $RPM_BUILD_ROOT%{prefix}/man/man5
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT/var/log/vtund
install -d $RPM_BUILD_ROOT/var/lock/vtund

make install INSTALL_OWNER=

install scripts/vtund.rc.red_hat $RPM_BUILD_ROOT/etc/rc.d/init.d/vtund

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf ../%{name}-%{version}

%files
%defattr(644,root,root)
%doc ChangeLog Credits FAQ README README.Setup README.Shaper TODO
%doc TODO vtund.conf 
%attr(755,root,root) %config /etc/rc.d/init.d/vtund
%attr(600,root,root) %config /etc/vtund.conf
%attr(755,root,root) %{prefix}/sbin/vtund
%attr(755,root,root) %dir /var/log/vtund
%attr(755,root,root) %dir /var/lock/vtund
%{prefix}/man/man8/vtund.8*
%{prefix}/man/man8/vtun.8*
%{prefix}/man/man5/vtund.conf.5*

%changelog
* Mon May 29 2000 Michael Tokarev <mjt@tls.msk.ru>
- Allow to build as non-root (using new INSTALL_OWNER option)
- Added vtund.conf.5 manpage
- Allow compressed manpages
- Added cleanup of old $RPM_BUILD_ROOT at beginning of %install stage

* Sat Mar 04 2000 Dag Wieers <dag@mind.be> 
- Added USE_SOCKS compile option.
- Added Prefix-header

* Sat Jan 29 2000 Dag Wieers <dag@mind.be> 
- Replaced SSLeay-dependency by openssl-dependency
- Replaced README.Config by README.Setup
- Added TODO

* Tue Nov 23 1999 Dag Wieers <dag@mind.be> 
- Added Url and Obsoletes-headers
- Added ChangeLog ;)
- Changed summary
