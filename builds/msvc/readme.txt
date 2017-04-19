For building on Windows, use:

     cd build
     ./build.bat

This requires that the CMD.EXE be created using the DevStudio Tools link to create a CMD.EXE window. Also, make sure that the name of the project folder is libzmq (not e.g. libzmq-master) as this is required for correct linking.

Visual Studio product and C++ compiler Versions:

Visual C++ 2008 => Visual C++ 9
Visual C++ 2010 => Visual C++ 10
Visual C++ 2012 => Visual C++ 11
Visual C++ 2013 => Visual C++ 12
Visual C++ 2015 => Visual C++ 14
Visual C++ 2017 => Visual C++ 15

Note that solution file icons reflect the compiler version ([9], [10], [11], [12], [14], [15]), not the product version.

The vs2017/vs2015/vs2013/vs2012/vs2010 solution and project files differ only in versioning.

More info here:

http://en.wikipedia.org/wiki/Visual_C%2B%2B

If multiple DevStudio versions are installed, you can run build.bat in separate windows each created by the desired DevStudio target.

To build for all versions of Visual Studio (excluding vs2008), you can run buildall.bat. This is generally a maintainer task.
