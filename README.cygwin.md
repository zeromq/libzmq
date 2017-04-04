libzmq-cygwin
=============

Definitive build fixes for cygwin  (See https://github.com/zeromq/pyzmq/issues/113 for partial solution)

What's changed:
  ./Makefile.am                       Add cygwin-specific target mostly the same as mingw
  ./configure.ac                      Add cygwin-specific target mostly the same as mingw
  ./tests/testutil.hpp                Lengthen socket timeout to 121 seconds
  
What's new:
  ./README.cygwin.md                  This file
  ./builds/cygwin                     Folder for cygwin-specific build files
  ./builds/cygwin/Makefile.cygwin     Makefile for cygwin targets
  
