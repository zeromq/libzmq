@ECHO OFF
@setlocal
::
:: uses the environment from the DevStudio CMD window to figure out which version to build
::

set VSVER=%VSINSTALLDIR:~-5,2%
set DIRVER=%VSVER%
if %VSVER% gtr 10 set /a DIRVER = DIRVER + 1

CALL buildbase.bat ..\vs20%DIRVER%\libzmq.sln %VSVER%

:- CALL buildbase.bat ..\vs2015\libzmq.sln 14
:- ECHO.
:- CALL buildbase.bat ..\vs2013\libzmq.sln 12
:- ECHO.
:- CALL buildbase.bat ..\vs2012\libzmq.sln 11
:- ECHO.
:- CALL buildbase.bat ..\vs2010\libzmq.sln 10
:- ECHO.

@endlocal
PAUSE
