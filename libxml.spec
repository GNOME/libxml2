# Note that this is NOT a relocatable package
%define ver      0.30
%define rel      1
%define prefix   /usr

Summary: libXML library
Name: libxml
Version: %ver
Release: %rel
Copyright: LGPL
Group: X11/Libraries
Source: ftp://ftp.gnome.org/pub/GNOME/sources/libxml-%{ver}.tar.gz
BuildRoot: /var/tmp/libxml-root
Packager: Michael Fulbright <msf@redhat.com>
URL: http://www.gnome.org
Prereq: /sbin/install-info
Docdir: %{prefix}/doc

%description
This library allows you to manipulate XML files.

%package devel
Summary: Libraries, includes, etc to develop libxml applications
Group: X11/libraries
Requires: libxml

%description devel
Libraries, include files, etc you can use to develop libxml applications.


%changelog

* Sun Oct  4 10:49:04 EDT 1998 Daniel Veillard <Daniel.Veillard@w3.org>

- Added xml-config to the package

* Thu Sep 24 1998 Michael Fulbright <msf@redhat.com>

- Built release 0.30

%prep
%setup

%build
# Needed for snapshot releases.
if [ ! -f configure ]; then
  CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh --prefix=%prefix 
else
  CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%prefix 
fi

if [ "$SMP" != "" ]; then
  (make "MAKE=make -k -j $SMP"; exit 0)
  make
else
  make
fi

%install
rm -rf $RPM_BUILD_ROOT

make prefix=$RPM_BUILD_ROOT%{prefix} install


%clean
#rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-, root, root)

%doc AUTHORS ChangeLog NEWS README COPYING COPYING.LIB TODO
%{prefix}/lib/lib*.so.*
%{prefix}/bin/xml-config

%files devel
%defattr(-, root, root)

%{prefix}/lib/lib*.so
%{prefix}/lib/*a
%{prefix}/lib/*.sh
%{prefix}/include/*
