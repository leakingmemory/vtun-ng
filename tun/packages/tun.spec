%define name	tun
%define version	1.1
%define release	7.2

# get the distro mark (eg rh70)
%define	_dis	%(case `rpm -qf /etc/issue 2>/dev/null` in (fedora-*) echo fc ;; (mandrake-*) echo mdk ;; (openlinux-*) echo ol ;; (redhat-*) echo rh;; (tao-*) echo tao ;; (whitebox-*) echo wb ;; (xos-*) echo xos ;; esac)
%define _tro	%(rpm -qf --qf "%%{version}" /etc/issue | sed 's/\\.//g' )

%{!?kernel:%define kernel %(rpm -q kernel-source --qf '%{RPMTAG_VERSION}-%{RPMTAG_RELEASE}' | tail -1)}
%define	kversion %(echo "%{kernel}" | sed -e 's|-.*||')
%define	krelease %(echo "%{kernel}" | sed -e 's|.*-||')
%define devstyl	%(echo "%{kversion}" | awk -F. '{print $1"."$2;}')
%define	modchr	%(case "%{devstyl}" in (2.2) echo 'char-major-90' ;; (2.4) echo 'char-major-10-200' ;; esac)

# start delineating which distros need nodes built.
%define	donode	%(case "%{_dis}%{_tro}" in (rhel4|fc?|tao*|xos*|wb*) echo '0' ;; (*) echo '1' ;; esac)
%define	doconf	%(case "%{_dis}%{_tro}" in (rhel4*|fc?) echo '0' ;; (*) echo '1' ;; esac)

#for OpenLinux crunchy goodness
%define	_buildshell	%([ -x /bin/bash2 ] && echo /bin/bash2 || echo /bin/bash )

Name: 		%{name}
Version: 	%{version}
Release: 	%{release}
Copyright: 	GPL
Group: 		System/Drivers
Url: 		http://vtun.sourceforge.net/tun/
Source: 	http://vtun.sourceforge.net/tun/%{name}-%{version}.tar.gz
Summary: 	Universal TUN/TAP device driver.
Vendor: 	Maxim Krasnyansky <max_mk@yahoo.com>
Packager: 	Bishop Clark (LC957) <bishop@platypus.bc.ca>
BuildRoot: 	/var/tmp/%{name}-%{version}-buildroot-%(id -u -n)
Requires:	%{_bindir}/diff %{_bindir}/patch /bin/grep

#doesn't work
%if "%{devstyl}" == "2.2"
Requires:	kernel=%{kernel}
%endif

%description
  TUN/TAP provides packet reception and transmission for user space programs. 
  It can be viewed as a simple Point-to-Point or Ethernet device, which 
  instead of receiving packets from a physical media, receives them from 
  user space program and instead of sending packets via physical media 
  writes them to the user space program. 

  The tun package provides a simple Glue package which can be easily
  listed as a requirement by tun-using 3rd-party projects.  The tun
  package performs the necessary steps or delivers the necessary files
  in order to prepare the target system for installation of the
  3rd-party app.  Until such time as every conceivable tun-using
  target environment is standardized, including the run RPM in a
  dependencies list easily ensures that the 3rd part application is
  properly configured by a small, neutral, common package.

%prep
%if %{donode}
[ `id -u -n` != "root" ] && echo "You need to be root on UL to use mknod." && exit 1
%endif
%setup -n %{name}-%{version}
./configure

%build
make 

# the alteration to the install section is intended to supply ONLY the
# files required for each platform.  Given the magic with the tun
# module checking to see if it needs to be built, some magic with
# %files -f is required.

%install
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT

install -m 755 -d $RPM_BUILD_ROOT/lib/modules/%{kversion}/net

#schroedinger's tun.o
cat <<EOF > listA
%defattr(644,root,root)
%doc FAQ README
EOF
if [ -f linux/tun.o ]; then
install -m 644 linux/tun.o $RPM_BUILD_ROOT/lib/modules/%{kversion}/net
 echo "%attr(600,root,root) /lib/modules/"%{kversion}"/net/tun.o" >> listA
fi
%if %{donode}
install -m 755 -d $RPM_BUILD_ROOT/dev
install -m 755 -d $RPM_BUILD_ROOT/dev/net
if [ %devstyl = 2.4 ]; then 
 mknod $RPM_BUILD_ROOT/dev/net/tun c 10 200
 echo "%attr(600,root,root) /dev/net/tun" >> listA
elif [ %devstyl = 2.2 ]; then
 for I in 0 1 2 3 4 5 6 7 8 9 ; do 
  mknod $RPM_BUILD_ROOT/dev/tun$I c 90 $I
  mknod $RPM_BUILD_ROOT/dev/tap$I c 90 $(($I+128))
  echo "%attr(600,root,root) /dev/tun$I" >> listA
  echo "%attr(600,root,root) /dev/tap$I" >> listA
 done
fi
%endif

%clean
[ $RPM_BUILD_ROOT != / ] && rm -rf $RPM_BUILD_ROOT

%if %{doconf}
%post
#add module into the modules.conf
cp /etc/modules.conf /etc/modules.conf.pre-mod
grep -v "%{modchr}" /etc/modules.conf | \
    diff /etc/modules.conf -  | patch -sb /etc/modules.conf
(cat /etc/modules.conf && echo  "alias %{modchr} tun") | \
    diff /etc/modules.conf -  | patch -s /etc/modules.conf
depmod -A
%endif

%if %{doconf}
%postun
#add module into the modules.conf
cp /etc/modules.conf /etc/modules.conf.pre-mod
grep -v "%{modchr}" /etc/modules.conf | \
    diff /etc/modules.conf -  | patch -sb /etc/modules.conf
depmod -A
%endif

%files -f listA

#date +"%a %b %d %Y"
%changelog
* Sun Apr 10 2005 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-7.1
- move the devstyl macro to more of a macro.
- change the risky uname-r bits to more chroot-friendly rpm-q
  invocation
- incorporate the kversion and krelease bits so they work in chroot
  builds too.
- start work to separate which distros need nodes built and which ones
  do not - and ensure we're root only when we need to be, thus making
  it easier to build as non-root where we can.
- re-enable kernel-NVR-deps where we deliver a tun.o
- lose the useless isUL macro; that whole project was as failing as
  the cooperation on which it was based.
- expand description because some people just don't see past their own
  project.
- simplify #post and don't do anything if we don't need to.

* Thu Dec 20 2001 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-6
- edit spec file to account for continuing COL/rpm306 builds like on
  20011112

* Mon Dec 03 2001 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-5
- semi-intelligent tun module addition/removal, with a checker
  warning.

* Tue Nov 20 2001 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-4
- tun/tap devices on kernel 2.2 now 0-9 from 0-3.  Cleaned up creation
  routine.

* Fri Nov 16 2001 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-3
- the kernel=%%(uname -r)Requires: line doesn't work.  Removing for
  now.
- change to buildshell part to on-the-fly do bash2.  RH62 hated it
  before.

* Mon Nov 12 2001 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-2
- Added minor change to support COL 31 builds
- more commenting, to explain weird stuff.

* Wed Oct 31 2001 Bishop Clark (LC957) <bishop@platypus.bc.ca>		1.1-1lc1
- remove directory so repeat builds succeed (3rd time)
- fixed a schroedinger's tun problem with trying to install or package
  nonexistent files
- only package files required for the target (no 2.4 devs on 2.2)
- more accurately tracks the kernel version
