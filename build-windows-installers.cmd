@echo off
setlocal

set WITH_OPENPGM=true
set WITH_DOC=true

:: Remove old build files
echo Cleaning build area ...
rmdir /s /q build 2> null
md build\x86\v90 build\x86\v100 build\x86\v110 build\x86\v110_xp build\x86\v120 2> null
md build\x64\v90 build\x64\v100 build\x64\v110 build\x64\v120 2> null

echo Starting build ...
call:buildx86 build\x86 ..\..
call:buildx64 build\x64 ..\..

echo Build finished.
goto:eof

:buildx86
echo Building targets for x86 ...
setlocal
cd %~1\v90
call "%ProgramFiles(x86)%\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" x86
cmake -G "Visual Studio 12" ..\..\.. -T "v90" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug /target:ALL_BUILD ZeroMQ.sln >> build.log && msbuild /nologo /property:Configuration=Release /target:ALL_BUILD ZeroMQ.sln >> build.log
for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
cd ..\v100
cmake -G "Visual Studio 12" ..\..\.. -T "v100" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release ALL_BUILD.vcxproj >> build.log
for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
cd ..\v110
cmake -G "Visual Studio 12" ..\..\.. -T "v110" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release ALL_BUILD.vcxproj >> build.log
for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
cd ..\v120
cmake -G "Visual Studio 12" ..\..\.. -T "v120" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release ALL_BUILD.vcxproj >> build.log
for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
cd ..\v110_xp
cmake -G "Visual Studio 12" ..\..\.. -T "v110_xp" -DWITH_OPENPGM=%WITH_OPENPGM% -DWITH_DOC=%WITH_DOC% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release PACKAGE.vcxproj >> build.log
(
  dir *.exe
  for /D %%f in (lib\*) do dir %%f\*.dll
) | findstr "\/"
cd %~2
endlocal
goto:eof

:buildx64
echo Building targets for x64 ...
cd %~1

setlocal
call "%ProgramFiles(x86)%\Microsoft Visual Studio 12.0\VC\vcvarsall.bat" x64

:: If linker crashes out with LNK1000 error install KB948127 to fix
:: https://connect.microsoft.com/VisualStudio/Downloads/DownloadDetails.aspx?DownloadID=11399
(
  cd v90
  cmake -G "Visual Studio 12 Win64" ..\..\.. -T "v90" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug /target:ALL_BUILD ZeroMQ.sln >> build.log && msbuild /nologo /property:Configuration=Release /target:ALL_BUILD ZeroMQ.sln >> build.log
  for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
  cd ..
)
(
  cd v100
  cmake -G "Visual Studio 12 Win64" ..\..\.. -T "v100" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release ALL_BUILD.vcxproj >> build.log
  for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
  cd ..
)
(
  cd v110
  cmake -G "Visual Studio 12 Win64" ..\..\.. -T "v110" -DWITH_OPENPGM=%WITH_OPENPGM% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release ALL_BUILD.vcxproj >> build.log
  for /D %%f in (lib\*) do dir %%f\*.dll | findstr "\/"
  cd ..
)
(
  cd v120
  cmake -G "Visual Studio 12 Win64" ..\..\.. -T "v120" -DWITH_OPENPGM=%WITH_OPENPGM% -DWITH_DOC=%WITH_DOC% > build.log && msbuild /nologo /property:Configuration=Debug ALL_BUILD.vcxproj >> build.log && msbuild /nologo /property:Configuration=Release PACKAGE.vcxproj >> build.log
  (
    dir *.exe
    for /D %%f in (lib\*) do dir %%f\*.dll
  ) | findstr "\/"
  cd ..
)

endlocal
cd %~2
goto:eof