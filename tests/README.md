#   Guidelines for tests

Write your test case as if you were writing clean application code. It should be safe to compile on all platforms.

The only include file you should use is `testutil.hpp`. Do not include files from src. Do not use the internal libzmq API or your test case is fair game to be deleted.

If you must write non-portable code, wrap it in #ifdefs to ensure it will compile and run on all systems.

Note that testutil.hpp includes platform.h. Do not include it yourself as it changes location depending on the build system and OS.

All sources must contain the correct header. Please copy from test_system.cpp if you're not certain.


