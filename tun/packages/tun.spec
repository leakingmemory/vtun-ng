%define name	tun
%define version	1.0
%define release	1
%define prefix	/

Name: %{name}
Version: %{version}
Release: %{release}
Copyright: GPL
Group: System/Drivers
Url: http://vtun.sourceforge.net/
Source: http://vtun.sourceforge.net/%{name}-%{version}.tar.gz
Summary: Virtual tunnel over TCP/IP networks.
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

%build
./configure
make 

%install
make
install -d $RPM_BUILD_ROOT/lib/modules/net
install -m 644 -o root -g root tun.o $RPM_BUILD_ROOT/lib/modules/net

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf ../%{name}-%{version}

%files
%defattr(644,root,root)
%doc FAQ README
%attr(755,root,root) %{prefix}/lib/modules/net/tun.o
