@echo off
:-  Needs Visual Studio 2015
"\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\vcvars32.bat"
msbuild /m /v:m project.sln
