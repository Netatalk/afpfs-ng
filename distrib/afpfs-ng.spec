Summary: Apple Filing Protocol client
Distribution: Fedora Core 6
Name: afpfs-ng
Version: 0.4
Release: 1
URL: http://sourceforge.net/projects/afpfs-ng/
Source0: %{name}-%{version}.tar.bz2
License: GPL
Group: System Environment/Base
BuildRoot: %{_tmppath}/%{name}-root
Packager: Houritsuchu <houritsuchu@hotmail.com>
BuildRequires: fuse-devel libgcrypt-devel
Requires: libgcrypt

%description
 afpfs-ng is an Apple Filing Protocol client that will allow a Linux system to see files exported from a Mac OS system with AFP over TCP.

%prep
%setup -q

%build
aclocal
libtoolize --force --copy
autoheader
automake --add-missing --include-deps --foreign
autoconf
%configure
make

%install
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}/

%files
%defattr(-,root,root)
/usr/bin/afpfsd
/usr/bin/afp_client
%doc COPYING README AUTHORS ChangeLog docs/README.html

%changelog
* Sun Feb 11 2007 Alex deVries <alexthepuffin@gmail.com>
- Updated to 0.4

* Tue Nov 28 2006 Houritsuchu <houritsuchu@hotmail.com>
- Initial build.
