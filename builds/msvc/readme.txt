Visual Studio product and C++ compiler Versions:

Visual C++ 2008 => Visual C++ 9
Visual C++ 2010 => Visual C++ 10
Visual C++ 2012 => Visual C++ 11
Visual C++ 2013 => Visual C++ 12

Note that solution file icons reflect the compiler version ([9], [10], [11], [12]), not the product version.

More info here:

http://en.wikipedia.org/wiki/Visual_C%2B%2B


Project configuration redundancies and inconsistencies:

The vs2012 and vs2010 solution and project files differ only in versioning.
The vs2012 and vs2010 configurations are missing build configurations.
It would make sense to rationalize these two older configurations with vs2013 but this may impact external expectations.

vs2010/properties and vs2012/properties are redundant project subdirectories.
vs2013/properties is a unique properties subdirectory.
The three subdirectories could be rationalized, but this would change existing output locations for the older two.

The current configuration in vs2008, vs2010 and vs2012 outputs produce output conflicts.
The vs2013 outputs are cleanly isolated from the other platform version outputs.