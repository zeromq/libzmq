#   Guidelines for tests

Write your test case as if you were writing clean application code. It should be safe to compile on all platforms.

The only include file you should use is `testutil.hpp`. Do not include files from src. Do not use the internal libzmq API or your test case is fair game to be deleted.

If you must write non-portable code, wrap it in #ifdefs to ensure it will compile and run on all systems.

Note that testutil.hpp includes platform.h. Do not include it yourself as it changes location depending on the build system and OS.

All sources must contain the correct header. Please copy from test_system.cpp if you're not certain.

Please use only ANSI C99 in test cases, no C++. This is to make the code more reusable.

On many slower environments, like embedded systems, VMs or CI systems, test might
fail because it takes time for sockets to settle after a connect. If you need
to add a sleep, please be consistent with all the other tests and use:
  msleep (SETTLE_TIME);

# Building tests in Windows

According to the version of your compiler, you should adapt the path `libzmq.lib` in the file `tests/CMakeLists.txt`.

Install CMAKE
CMD> CMAKE libzmq/tests
CMD> tests.sln
CMD> # build all projects in the solution

