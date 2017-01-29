REM run cmake for UWP

SET CMAKE="c:\program files\cmake\bin\cmake"

REM %CMAKE% --help
%CMAKE% -H. -B..\gen\libzmq_uwp -G"Visual Studio 14 2015 Win64" -DCMAKE_SYSTEM_NAME=WindowsStore -DCMAKE_SYSTEM_VERSION=10.0 -DENABLE_CURVE=OFF -DZMQ_BUILD_TESTS=OFF
