%define name	tun
%define version	1.1
%define release	1
%define prefix	/

Name: %{name}
Version: %{version}
Release: %{release}
Copyright: GPL
Group: System/Drivers
Url: http://vtun.sourceforge.net/tun/
Source: http://vtun.sourceforge.net/tun/%{name}-%{version}.tar.gz
Summary: Universal TUN/TAP device driver.
Vendor: Maxim Krasnyansky <max_mk@yahoo.com>
Packager: Maxim Krasnyansky <max_mk@yahoo.com>
BuildRoot: /var/tmp/%{name}-%{version}-build
Prefix: %{prefix}

%description
  TUN/TAP provides packet reception and transmission for user space programs. 
  It can be viewed as a simple Point-to-Point or Ethernet device, which 
  instead of receiving packets from a physical media, receives them from 
  user space program and instead of sending packets via physical media 
  writes them to the user space program. 

%prep
%setup -n %{name}-%{version}
./configure

%build
make 

%install
make
install -m 755 -o root -g root -d $RPM_BUILD_ROOT/lib/modules/net
install -m 644 -o root -g root linux/tun.o $RPM_BUILD_ROOT/lib/modules/net

install -m 755 -o root -g root -d $RPM_BUILD_ROOT/dev
install -m 755 -o root -g root -d $RPM_BUILD_ROOT/dev/net
mknod $RPM_BUILD_ROOT/net/dev/tun c 10 200
mknod $RPM_BUILD_ROOT/dev/tun0 c 90 0
mknod $RPM_BUILD_ROOT/dev/tun1 c 90 1
mknod $RPM_BUILD_ROOT/dev/tun2 c 90 2
mknod $RPM_BUILD_ROOT/dev/tap0 c 90 128
mknod $RPM_BUILD_ROOT/dev/tap1 c 90 129
mknod $RPM_BUILD_ROOT/dev/tap2 c 90 130

%clean
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT

%post
depmod -a

%postun
depmod -a

%files
%defattr(644,root,root)
%doc FAQ README
%attr(644,root,root) %{prefix}/lib/modules/net/tun.o
%attr(600,root,root) %{prefix}/dev/net/tun
%attr(600,root,root) %{prefix}/dev/tun0
%attr(600,root,root) %{prefix}/dev/tun1
%attr(600,root,root) %{prefix}/dev/tun2
%attr(600,root,root) %{prefix}/dev/tap0
%attr(600,root,root) %{prefix}/dev/tap1
%attr(600,root,root) %{prefix}/dev/tap2
