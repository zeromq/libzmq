# We do not want to install Jzmq.class file
# user has to copy it to the right location.
#jzmqdir = /tmp

jarfile = Zmq.jar
jardir = $(datadir)/java

$(jarfile): $(dist_noinst_JAVA)
	$(JAR) cf $(JARFLAGS) $@ org/zmq/*.class

jar_DATA = $(jarfile)

dist_noinst_JAVA = \
	org/zmq/Context.java \
	org/zmq/Socket.java \
    org/zmq/Poller.java

lib_LTLIBRARIES = libjzmq.la
libjzmq_la_SOURCES = \
	Context.cpp \
	Socket.cpp \
    Poller.cpp
nodist_libjzmq_la_SOURCES = \
	org_zmq_Context.h \
	org_zmq_Socket.h \
    org_zmq_Poller.h

libjzmq_la_CXXFLAGS = @JAVA_INCLUDE@ -I$(top_srcdir)/bindings/c -Wall
libjzmq_la_LDFLAGS = -version-info @JLTVER@
libjzmq_la_LIBADD = $(top_builddir)/src/libzmq.la

BUILT_SOURCES = \
	org/zmq/Context.class \
	org_zmq_Context.h \
	org/zmq/Socket.class \
	org_zmq_Socket.h \
	org/zmq/Poller.class \
	org_zmq_Poller.h

CLEANFILES = \
	org/zmq/Context.class \
	org_zmq_Context.h \
	org/zmq/Socket.class \
	org_zmq_Socket.h \
	org/zmq/Poller.class \
	org_zmq_Poller.h \
	Zmq.jar

$(srcdir)/Context.cpp: org_zmq_Context.h

org_zmq_Context.h: org/zmq/Context.class
	$(CLASSPATH_ENV) $(JAVAH) -jni -classpath . org.zmq.Context

./org/zmq/Context.class: classdist_noinst.stamp

$(srcdir)/Socket.cpp: org_zmq_Socket.h

org_zmq_Socket.h: org/zmq/Socket.class
	$(CLASSPATH_ENV) $(JAVAH) -jni -classpath . org.zmq.Socket

./org/zmq/Socket.class: classdist_noinst.stamp

$(srcdir)/Poller.cpp: org_zmq_Poller.h

org_zmq_Poller.h: org/zmq/Poller.class
	$(CLASSPATH_ENV) $(JAVAH) -jni -classpath . org.zmq.Poller

./org/zmq/Poller.class: classdist_noinst.stamp

dist-hook:
	-rm $(distdir)/*.h

