%define name	vtun
# temporary version for timestamped releases
%define version	3.0.0
%define release	0

#this part NEEDS to be expanded
%define IsSuSE	%( [ -f /etc/SuSE-release ] && echo 1 || echo 0 )
%if %{IsSuSE}
 %define rc_dir   /etc/init.d
 %define lock_dir /var/lock/subsys/vtunnel
 %define log_dir  /var/log/vtunnel
%else
 %define rc_dir /etc/rc.d/init.d
 %define lock_dir /var/lock/vtund
 %define log_dir  /var/log/vtund
%endif

# By default, builds without socks-support.
# To build with socks-support, issue:
#   rpm --define "USE_SOCKS yes" ...

# By default, builds with LZO support (available for any RPM system)
# To disable LZO, issue:
#   rpm --define "NO_USE_LZO yes" ...

Name: %{name}
Version: %{version}
Release: %{release}
Copyright: GPL
Group: System Environment/Daemons
Url: http://vtun.sourceforge.net/
Source: http://vtun.sourceforge.net/%{name}-%{version}.tar.gz
Summary: Virtual tunnel over TCP/IP networks.
Vendor: Maxim Krasnyansky <max_mk@yahoo.com>
#Packager: Dag Wieers <dag@mind.be> 
Packager: Bishop Clark (LC957) <bishop@platypus.bc.ca>
BuildRoot: %{tmpdir}/%{name}-%{version}-root-%(id -u -n)
Obsoletes: vppp
%{!?NO_USE_LZO:Buildrequires: lzo-devel}
%{!?_without_ssl:BuildRequires: openssl-devel }
BuildRequires: bison
BuildRequires: flex
BuildRequires: autoconf
BuildRequires: automake

# Caldera has funny zlib
%if %( rpm -q OpenLinux >/dev/null 2>/dev/null && echo 0 || echo 1 )
BuildRequires: zlib-devel
%else
BuildRequires: libz-devel
%endif

%description
VTun provides the method for creating Virtual Tunnels over TCP/IP
networks and allows to shape, compress, encrypt traffic in that
tunnels.  Supported type of tunnels are: PPP, IP, Ethernet and most of
other serial protocols and programs.

VTun is easily and highly configurable: it can be used for various
network tasks like VPN, Mobil IP, Shaped Internet access, IP address
saving, etc.  It is completely a user space implementation and does
not require modification to any kernel parts.

This package is built with%{!?USE_SOCKS:out} SOCKS-support.
%{?NO_USE_LZO:This package is built without LZO support.}

%prep

%setup -n %{name}
%configure			   \
            --prefix=%{_exec_prefix} 	   \
	    --sysconfdir=/etc 	   \
	    --localstatedir=%{_var}   \
%{?NO_USE_LZO: --disable-lzo} \
%{?USE_SOCKS: --enable-socks}

%build
make %{?IsSuSE: LOCK_DIR=%{lock_dir} STAT_DIR=/var/log/vtunnel}

%install
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT
#deprecated - please check that this deletion does not harm SuSE build
#install -d $RPM_BUILD_ROOT%{_sbindir}
#install -d $RPM_BUILD_ROOT%{_mandir}/man8
#install -d $RPM_BUILD_ROOT%{_mandir}/man5
#install -d $RPM_BUILD_ROOT%{log_dir}
#install -d $RPM_BUILD_ROOT%{lock_dir}
install -d $RPM_BUILD_ROOT%{rc_dir}
 if [ x%{IsSuSE} = x1 ]; then
install scripts/vtund.rc.suse $RPM_BUILD_ROOT%{rc_dir}/vtund
 else 
install scripts/vtund.rc.red_hat $RPM_BUILD_ROOT%{rc_dir}/vtund
 fi
make install SBIN_DIR=$RPM_BUILD_ROOT%{_sbindir} \
        MAN_DIR=$RPM_BUILD_ROOT%{_mandir} \
        ETC_DIR=$RPM_BUILD_ROOT/etc \
        VAR_DIR=$RPM_BUILD_ROOT%{_var} \
        LOCK_DIR=$RPM_BUILD_ROOT%{lock_dir} \
	INSTALL_OWNER=

if [ x%{IsSuSE} = x1 ]; then
# SuSE RC.CONFIG templates
install -d $RPM_BUILD_ROOT/var/adm/fillup-templates
install -m 644 scripts/vtund.rc.suse.config $RPM_BUILD_ROOT/var/adm/fillup-templates/rc.config.vtund

# rcvtund
ln -sf ../..%{rc_dir}/vtund $RPM_BUILD_ROOT/usr/sbin/rcvtund

fi

%post
if [ x%{IsSuSE} = x1 ]; then
#rc config
echo "Updating etc/rc.config..."
if [ -x bin/fillup ] ; then
  bin/fillup -q -d = etc/rc.config var/adm/fillup-templates/rc.config.vtund
else
  echo "ERROR: fillup not found. This should not happen. Please compare"
  echo "etc/rc.config and var/adm/fillup-templates/rc.config.vtund and"
  echo "update by hand."
fi
sbin/insserv etc/init.d/vtund
fi

%clean
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root)
%doc ChangeLog Credits FAQ README README.Setup README.Shaper TODO
%doc TODO vtund.conf 
%attr(755,root,root) %config %{rc_dir}/vtund
%attr(600,root,root) %config(noreplace) /etc/vtund.conf
%attr(755,root,root) %{_sbindir}/vtund
%attr(755,root,root) %dir %{log_dir}
%attr(755,root,root) %dir %{lock_dir}
%{_mandir}/man8/vtund.8*
#%{_mandir}/man8/vtun.8*
%{_mandir}/man5/vtund.conf.5*
%if %{IsSuSE}
%attr(755,root,root) %{_sbindir}/rcvtund
/var/adm/fillup-templates/rc.config.vtund
%endif

%changelog
* Sat Aug 17 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-5
- fix GROUP for amanda's genhdlist and Michael Van Donselaar

* Tue Feb 12 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-4
- Deprecated redundant directory creation in install
- More undisputed patches by Willems Luc for SuSE support
- Update of one SuSE config file, addition of another as per 
  Willems Luc

* Mon Jan 21 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-3
- Macros updating as per 2.5 for better cross-distro build
- Added NO_USE_LZO compile option as per Willems Luc
- Very initial SuSE 7.3 support as per Willems Luc
- Removed packaging of vtun->vtund symlink in man8 as per build
  behaviour

* Mon Jan 14 2002 Bishop Clark (LC957) <bishop@platypus.bc.ca> 2.5-2
- Noreplace to vtund.conf to prevent Freshen from clobbering config.
- Added buildrequires to prevent failed builds.

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
