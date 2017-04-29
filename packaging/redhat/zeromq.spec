# To build with draft APIs, use "--with drafts" in rpmbuild for local builds or add
#   Macros:
#   %_with_drafts 1
# at the BOTTOM of the OBS prjconf
%bcond_with drafts
%if %{with drafts}
%define DRAFTS yes
%else
%define DRAFTS no
%endif
%define lib_name libzmq5
Name:          zeromq
Version:       4.2.3
Release:       1%{?dist}
Summary:       The ZeroMQ messaging library
Group:         Applications/Internet
License:       LGPLv3+
URL:           http://www.zeromq.org/
Source:        http://download.zeromq.org/%{name}-%{version}.tar.gz
Prefix:        %{_prefix}
Buildroot:     %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires:  autoconf automake libtool libsodium-devel glib2-devel
%if ! (0%{?fedora} > 12 || 0%{?rhel} > 5)
BuildRequires:  e2fsprogs-devel
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
%endif
%if %{with pgm}
BuildRequires:  openpgm-devel
BuildRequires:  krb5-devel
%endif
BuildRequires: gcc, make, gcc-c++, libstdc++-devel, asciidoc, xmlto
Requires:      libstdc++

#
# Conditional build options
# Default values are:
#    --without-libgssapi_krb5
#    --without-libsodium
#    --without-pgm
#

# If neither macro exists, use the default value.
%{!?_with_libgssapi_krb5: %{!?_without_libgssapi_krb5: %define _without_libgssapi_krb5 --without-liblibgssapi_krb5}}
%{!?_with_libsodium: %{!?_without_libsodium: %define _without_libsodium --without-libsodium}}
%{!?_with_pgm: %{!?_without_pgm: %define _without_pgm --without-pgm}}

# It's an error if both --with and --without options are specified
%{?_with_libgssapi_krb5: %{?_without_libgssapi_krb5: %{error: both _with_libgssapi_krb5 and _without_libgssapi_krb5}}}
%{?_with_libsodium: %{?_without_libsodium: %{error: both _with_libsodium and _without_libsodium}}}
%{?_with_pgm: %{?_without_pgm: %{error: both _with_pgm and _without_pgm}}}

%{?_with_libgssapi_krb5:BuildRequires: krb5-devel}
%{?_with_libgssapi_krb5:Requires: krb5-libs}

%{?_with_libsodium:BuildRequires: libsodium-devel}
%{?_with_libsodium:Requires: libsodium}

%{?_with_pgm:BuildRequires: openpgm-devel}
%{?_with_pgm:Requires: openpgm}

%ifarch pentium3 pentium4 athlon i386 i486 i586 i686 x86_64
%{!?_with_pic: %{!?_without_pic: %define _with_pic --with-pic}}
%{!?_with_gnu_ld: %{!?_without_gnu_ld: %define _with_gnu_ld --with-gnu_ld}}
%endif

%description
The 0MQ lightweight messaging kernel is a library which extends the
standard socket interfaces with features traditionally provided by
specialised messaging middleware products. 0MQ sockets provide an
abstraction of asynchronous message queues, multiple messaging
patterns, message filtering (subscriptions), seamless access to
multiple transport protocols and more.

%package -n %{lib_name}
Summary:   Shared Library for ZeroMQ
Group:     Productivity/Networking/Web/Servers
Conflicts: zeromq

%description -n %{lib_name}
The 0MQ lightweight messaging kernel is a library which extends the
standard socket interfaces with features traditionally provided by
specialised messaging middleware products. 0MQ sockets provide an
abstraction of asynchronous message queues, multiple messaging
patterns, message filtering (subscriptions), seamless access to
multiple transport protocols and more.

This package contains the ZeroMQ shared library.

%package devel
Summary:  Development files and static library for the ZeroMQ library
Group:    Development/Libraries
Requires: %{lib_name} = %{version}-%{release}, pkgconfig

%description devel
The 0MQ lightweight messaging kernel is a library which extends the
standard socket interfaces with features traditionally provided by
specialised messaging middleware products. 0MQ sockets provide an
abstraction of asynchronous message queues, multiple messaging
patterns, message filtering (subscriptions), seamless access to
multiple transport protocols and more.

This package contains ZeroMQ related development libraries and header files.

%package -n libzmq-tools
Summary:   ZeroMQ tools
Group:     Productivity/Networking/Web/Servers

%description -n libzmq-tools
The 0MQ lightweight messaging kernel is a library which extends the
standard socket interfaces with features traditionally provided by
specialised messaging middleware products. 0MQ sockets provide an
abstraction of asynchronous message queues, multiple messaging
patterns, message filtering (subscriptions), seamless access to
multiple transport protocols and more.

This package contains tools such as curve_keygen to use with libzmq.

%prep
%setup -q

# Sed version number of openpgm into configure
%global openpgm_pc $(basename %{_libdir}/pkgconfig/openpgm*.pc .pc)
sed -i "s/openpgm-[0-9].[0-9]/%{openpgm_pc}/g" \
    configure*

%build
autoreconf -fi
%configure --enable-drafts=%{DRAFTS} \
    %{?_with_libsodium} \
    %{?_without_libsodium} \
    %{?_with_pgm} \
    %{?_without_pgm} \
    %{?_with_libgssapi_krb5} \
    %{?_without_libgssapi_krb5} \
    %{?_with_pic} \
    %{?_without_pic} \
    %{?_with_gnu_ld} \
    %{?_without_gnu_ld}

%{__make} %{?_smp_mflags}

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

# Install the package to build area
%{__make} check
%makeinstall

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%files -n %{lib_name}
%defattr(-,root,root,-)

# docs in the main package
%doc AUTHORS COPYING COPYING.LESSER NEWS

# libraries
%{_libdir}/libzmq.so.*

%{_mandir}/man7/zmq.7.gz

%files devel
%defattr(-,root,root,-)
%{_includedir}/zmq.h
%{_includedir}/zmq_utils.h

%{_libdir}/libzmq.la
%{_libdir}/libzmq.a
%{_libdir}/pkgconfig/libzmq.pc
%{_libdir}/libzmq.so

%{_mandir}/man3/zmq*
# skip man7/zmq.7.gz
%{_mandir}/man7/zmq_*

%files -n libzmq-tools
%defattr(-,root,root,-)
%{_bindir}/curve_keygen

%changelog
* Sun Nov 06 2016 Luca Boccassi <luca.boccassi@gmail.com>
- Add libzmq-tool to package curve_keygen in /usr/bin

* Sun Jul 31 2016 Luca Boccassi <luca.boccassi@gmail.com>
- Follow RPM standards and rename zeromq to libzmq5

* Sat Oct 25 2014 Phillip Mienk <mienkphi@gmail.com>
- Add --with/--without libgssapi_krb5 support following J.T.Conklin's pattern

* Sat Oct 18 2014 J.T. Conklin <jtc@acorntoolworks.com>
- Add --with/--without pgm support
- Add --with/--without libsodium support

* Tue Jun 10 2014 Tristian Celestin <tristian.celestin@outlook.com> 4.0.4
- Updated packaged files

* Mon Nov 26 2012 Justin Cook <jhcook@gmail.com> 3.2.2
- Update packaged files

* Fri Apr 8 2011 Mikko Koppanen <mikko@kuut.io> 3.0.0-1
- Update dependencies and packaged files

* Sat Apr 10 2010 Mikko Koppanen <mkoppanen@php.net> 2.0.7-1
- Initial packaging
