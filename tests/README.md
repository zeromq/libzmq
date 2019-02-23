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
  
#   Ensure proper cleanup

If a test program uses unity, it will execute test cases individually, and will continue to run further test cases if an assertion in one test case fails. However, the test case that had an assertion failure will be aborted.
To ensure that the resources of the test case are properly cleaned up, use appropriate setUp and tearDown functions. These are run by unity before each test case starts resp. after it ended (whether successfully or not).
The same setUp and tearDown function is used for all test cases in a test program.

For many test cases, the following setUp and tearDown functions will be appropriate:
	void setUp ()
	{
		setup_test_context ();
	}

	void tearDown ()
	{
		teardown_test_context ();
	}

Within the tests, do not use zmq_socket and zmq_close then but test_context_socket and test_context_socket_close instead. These functions will register/unregister sockets with the test_context. 
All sockets not closed when tearDown is executed, with forcibly be closed with linger=0 before terminating the context. Note that it is a misuse not to close sockets during successful test execution, 
and a warning will be output.

#   Building tests in Windows

The tests are only built via cmake, not when using the checked-in Visual Studio .sln files.
