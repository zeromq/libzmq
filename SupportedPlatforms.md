libzmq supports a large variety of platforms. The list of platforms can be found in the [README](README.md#platforms).
The degree to which this support is tested varies.

Platforms are currently assigned to one of the following categories:
- supported platforms with primary CI (travis-ci.org, appveyor.com): https://travis-ci.org/zeromq/libzmq, https://ci.appveyor.com/project/zeromq/libzmq
- supported platforms with secondary CI (openSUSE Build Service): https://build.opensuse.org/project/subprojects/network:messaging:zeromq
- supported platforms with known active users
- supported platforms without known active users
- unsupported platforms

Supported platforms with primary CI
- have builds and tests run for the master branch
- have builds and tests run for every pull request
- it is a precondition for merging a pull request that no builds or tests of these platforms are broken
- contributors can easily enable these builds and tests for their branches in their fork

Suported platforms with secondary CI
- have builds and tests run for the master branch
- these are monitored periodically by the project maintainers, and efforts are made to fix any broken builds or tests in a timely manner
- it is a precondition for a release that no builds or tests of these platforms are broken

Supported platforms with known active users
- have recently been reported to the maintainers (e.g. via pull requests modifying this document) as having working builds and possibly tests

Supported platforms without known active users
- have some platform-specific code within libzmq, but it is not known if it is still working
- have been reported to the maintainers as having working builds and possibly tests only significant time/changes ago 
- or are assumed to work due to similarity to the above platforms

Unsupported platforms
- are either reported to be non-working for some reason that is not trivial to fix or are explicitly missing some required platform-specific code

