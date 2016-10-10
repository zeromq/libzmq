@ECHO OFF
:: Usage: buildall.bat

:: Build all configurations for all solutions.
CALL buildbase.bat ..\vs2015\libzmq.sln 14
ECHO.
CALL buildbase.bat ..\vs2013\libzmq.sln 12
ECHO.
CALL buildbase.bat ..\vs2012\libzmq.sln 11
ECHO.
CALL buildbase.bat ..\vs2010\libzmq.sln 10
ECHO.

PAUSE
