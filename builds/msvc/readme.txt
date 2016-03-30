For building on Windows, use:

     ./configure.bat
     cd build
     ./buildall.bat

This requires that the CMD.EXE be created using the DevStudio Tools link to create a CMD.EXE windo.

Visual Studio product and C++ compiler Versions:

Visual C++ 2008 => Visual C++ 9
Visual C++ 2010 => Visual C++ 10
Visual C++ 2012 => Visual C++ 11
Visual C++ 2013 => Visual C++ 12
Visual C++ 2015 => Visual C++ 14

Note that solution file icons reflect the compiler version ([9], [10], [11], [12], [14]), not the product version.

The vs2015/vs2013/vs2012/vs2010 solution and project files differ only in versioning.

More info here:

http://en.wikipedia.org/wiki/Visual_C%2B%2B

If multiple DevStudio versions are installed on the machine, you can run buildall.bat on separate windows that each were created by the desired DevStudio target.

If you prefer to build all versions (or several) at the same time, you should uncomment the specific version desired in buildall.bat to build them from a single window.
