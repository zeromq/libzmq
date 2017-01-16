@ECHO OFF
@setlocal
REM Usage: [buildbase.bat ..\vs2013\mysolution.sln 12 [Clean]]

SET solution=%1
SET version=%2

:: supports passing in Clean as third argument if "make clean" behavior is desired
SET target=%3
SET ACTION=Building
if NOT "%target%" == "" set target=/t:%target%&set ACTION=Cleaning

SET log=build_%version%.log
SET tools=Microsoft Visual Studio %version%.0\VC\vcvarsall.bat
if "%version%" == "17" SET tools=Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat
SET environment="%programfiles(x86)%\%tools%"
IF NOT EXIST %environment% SET environment="%programfiles%\%tools%"
IF NOT EXIST %environment% GOTO no_tools

@ECHO %ACTION% %solution%

CALL %environment% x86 >%SystemDrive%\nul 2>&1
ECHO Platform=x86 2> %log%

ECHO Configuration=DynDebug
msbuild /m /v:n /p:Configuration=DynDebug /p:Platform=Win32 %solution% %target%>> %log% || GOTO error
ECHO Configuration=DynRelease
msbuild /m /v:n /p:Configuration=DynRelease /p:Platform=Win32 %solution% %target%>> %log% || GOTO error
ECHO Configuration=LtcgDebug
msbuild /m /v:n /p:Configuration=LtcgDebug /p:Platform=Win32 %solution% %target%>> %log% || GOTO error
ECHO Configuration=LtcgRelease
msbuild /m /v:n /p:Configuration=LtcgRelease /p:Platform=Win32 %solution% %target%>> %log% || GOTO error
ECHO Configuration=StaticDebug
msbuild /m /v:n /p:Configuration=StaticDebug /p:Platform=Win32 %solution% %target%>> %log% || GOTO error
ECHO Configuration=StaticRelease
msbuild /m /v:n /p:Configuration=StaticRelease /p:Platform=Win32 %solution% %target%>> %log% || GOTO error

CALL %environment% x86_amd64 >%SystemDrive%\nul 2>&1
ECHO Platform=x64

ECHO Configuration=DynDebug
msbuild /m /v:n /p:Configuration=DynDebug /p:Platform=x64 %solution% %target%>> %log% || GOTO error
ECHO Configuration=DynRelease
msbuild /m /v:n /p:Configuration=DynRelease /p:Platform=x64 %solution% %target%>> %log% || GOTO error
ECHO Configuration=LtcgDebug
msbuild /m /v:n /p:Configuration=LtcgDebug /p:Platform=x64 %solution% %target%>> %log% || GOTO error
ECHO Configuration=LtcgRelease
msbuild /m /v:n /p:Configuration=LtcgRelease /p:Platform=x64 %solution% %target%>> %log% || GOTO error
ECHO Configuration=StaticDebug
msbuild /m /v:n /p:Configuration=StaticDebug /p:Platform=x64 %solution% %target%>> %log% || GOTO error
ECHO Configuration=StaticRelease
msbuild /m /v:n /p:Configuration=StaticRelease /p:Platform=x64 %solution% %target%>> %log% || GOTO error

ECHO %ACTION% complete: %solution%
GOTO end

:error
ECHO *** ERROR, build terminated early, see: %log%
GOTO end

:no_tools
ECHO *** ERROR, build tools not found: %tools%

:end
@endlocal
