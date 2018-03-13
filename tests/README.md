#   Guidelines for tests

Write your test case as if you were writing clean application code. It should be safe to compile on all platforms.

Normally, you should only include the header files from the tests directory, e.g. `testutil.hpp`. Do not include files from src. Do not use the internal libzmq API. Tests for these should be placed in unittests instead.

If you must write non-portable code, wrap it in #ifdefs to ensure it will compile and run on all systems.

Note that testutil.hpp includes platform.h. Do not include it yourself as it changes location depending on the build system and OS.

All sources must contain the correct copyright header. Please copy from test_system.cpp if you're not certain.

Write new tests using the unity test framework. For an example, see test_sockopt_hwm.

Please use only ANSI C99 in test cases, no C++. This is to make the code more reusable.

On many slower environments, like embedded systems, VMs or CI systems, tests might
fail because it takes time for sockets to settle after a connect. If you need
to add a sleep, please be consistent with all the other tests and use:
  msleep (SETTLE_TIME);

#   Building tests in Windows

The tests are only built via cmake, not when using the checked-in Visual Studio .sln files.
