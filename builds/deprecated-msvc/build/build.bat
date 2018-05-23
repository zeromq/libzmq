@ECHO OFF
:: Usage: build.bat [Clean]
@setlocal

:: validate environment
if "%VSINSTALLDIR%" == "" @echo Error: Attempt to build without proper DevStudio environment.&@goto :done

:: record starting time
set STARTTIME=%DATE% %TIME%
@echo Start Time: %STARTTIME%


:: validate optional argument (and make sure it is spelled "Clean")
set MAKECLEAN=%%1
if NOT "%%1" == "" if /I "%%1" == "clean" set MAKECLEAN=Clean


::
:: uses the environment from the DevStudio CMD window to figure out which version to build
::

set VSVER=%VSINSTALLDIR:~-5,2%
set DIRVER=%VSVER%
if %VSVER% gtr 10 set /a DIRVER = DIRVER + 1

CALL buildbase.bat ..\vs20%DIRVER%\libzmq.sln %VSVER% %MAKECLEAN%

set STOPTIME=%DATE% %TIME%
@echo Stop  Time: %STOPTIME%
@echo Start Time: %STARTTIME%

:done
@endlocal
