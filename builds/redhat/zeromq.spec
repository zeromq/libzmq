Name:          zeromq
Version:       @PACKAGE_VERSION@
Release:       1%{?dist}
Summary:       Fastest. Messaging. Ever.
Group:         Applications/Internet
License:       LGPLv3+
URL:           http://www.zeromq.org/
Source:        http://www.zeromq.org/local--files/area:download/%{name}-%{version}.tar.gz
Prefix:        %{_prefix}
Buildroot:     %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: uuid-devel, gcc, make, gcc-c++, libstdc++-devel
Requires:      uuid, libstdc++

# Build pgm only on supported archs
%ifarch pentium3 pentium4 athlon i386 i486 i586 i686 x86_64
BuildRequires: glib2-devel
Requires: glib2
%endif

%description
Fast and lightweight messaging system designed with 
speed and reliability in mind.

%package devel
Summary:  Development headers
Group:    Development/Libraries
Requires: %{name} = %{version}-%{release}, pkgconfig

%description devel
Files needed for building applications with zeromq.

%package utils
Summary:  zeromq utilities
Group:    System Environment/Utilities
Requires: %{name} = %{version}-%{release}

%description utils
Performance testing utilities for zeromq.

%prep
%setup -q

%build
%ifarch pentium3 pentium4 athlon i386 i486 i586 i686 x86_64
  %configure --with-pgm
%else
  %configure
%endif

%{__make} %{?_smp_mflags}

%install
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

# Install the package to build area
%makeinstall

# copy the utility binaries
%{__cp} %{_builddir}/%{name}-%{version}/perf/local_lat %{buildroot}/%{_bindir}
%{__cp} %{_builddir}/%{name}-%{version}/perf/local_thr %{buildroot}/%{_bindir}
%{__cp} %{_builddir}/%{name}-%{version}/perf/remote_lat %{buildroot}/%{_bindir}
%{__cp} %{_builddir}/%{name}-%{version}/perf/remote_thr %{buildroot}/%{_bindir}

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%clean
[ "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)

# docs in the main package
%doc AUTHORS ChangeLog COPYING COPYING.LESSER NEWS README

# libraries
%{_libdir}/libzmq.so.0
%{_libdir}/libzmq.so.0.0.0

%attr(0755,root,root) %{_bindir}/zmq_forwarder
%attr(0755,root,root) %{_bindir}/zmq_queue
%attr(0755,root,root) %{_bindir}/zmq_streamer

%{_mandir}/man7/zmq.7.gz
%{_mandir}/man1/zmq_forwarder.1.gz
%{_mandir}/man1/zmq_queue.1.gz
%{_mandir}/man1/zmq_streamer.1.gz

%files utils
%attr(0755, root, root) %{_bindir}/local_lat
%attr(0755, root, root) %{_bindir}/local_thr
%attr(0755, root, root) %{_bindir}/remote_lat
%attr(0755, root, root) %{_bindir}/remote_thr

%files devel
%defattr(-,root,root,-)
%{_includedir}/zmq.h
%{_includedir}/zmq.hpp

%{_libdir}/libzmq.la
%{_libdir}/libzmq.a
%{_libdir}/pkgconfig/libzmq.pc
%{_libdir}/libzmq.so

%{_mandir}/man3/zmq_bind.3.gz
%{_mandir}/man3/zmq_close.3.gz
%{_mandir}/man3/zmq_connect.3.gz
%{_mandir}/man3/zmq_init.3.gz
%{_mandir}/man3/zmq_msg_close.3.gz
%{_mandir}/man3/zmq_msg_copy.3.gz
%{_mandir}/man3/zmq_msg_data.3.gz
%{_mandir}/man3/zmq_msg_init.3.gz
%{_mandir}/man3/zmq_msg_init_data.3.gz
%{_mandir}/man3/zmq_msg_init_size.3.gz
%{_mandir}/man3/zmq_msg_move.3.gz
%{_mandir}/man3/zmq_msg_size.3.gz
%{_mandir}/man3/zmq_poll.3.gz
%{_mandir}/man3/zmq_recv.3.gz
%{_mandir}/man3/zmq_send.3.gz
%{_mandir}/man3/zmq_setsockopt.3.gz
%{_mandir}/man3/zmq_socket.3.gz
%{_mandir}/man3/zmq_strerror.3.gz
%{_mandir}/man3/zmq_term.3.gz
%{_mandir}/man3/zmq_version.3.gz
%{_mandir}/man7/zmq_cpp.7.gz
%{_mandir}/man7/zmq_epgm.7.gz
%{_mandir}/man7/zmq_inproc.7.gz
%{_mandir}/man7/zmq_ipc.7.gz
%{_mandir}/man7/zmq_pgm.7.gz
%{_mandir}/man7/zmq_tcp.7.gz

%changelog
* Sat Apr 10 2010 Mikko Koppanen <mkoppanen@php.net> 2.0.7-1
- Initial packaging
