set(CMAKE_SYSTEM_NAME QNX)

set(arch gcc_ntox86)
set(ntoarch x86)
set(QNX_PROCESSOR x86)

set(CMAKE_C_COMPILER qcc )
set(CMAKE_C_COMPILER_TARGET ${arch})

set(CMAKE_CXX_COMPILER QCC -lang-c++ -g)
set(CMAKE_CXX_COMPILER_TARGET ${arch})

set(CMAKE_ASM_COMPILER qcc -V${arch})
set(CMAKE_ASM_DEFINE_FLAG "-Wa,--defsym,")

set(CMAKE_RANLIB $ENV{QNX_HOST}/usr/bin/nto${ntoarch}-ranlib
	    CACHE PATH "QNX ranlib Program" FORCE)
    set(CMAKE_AR $ENV{QNX_HOST}/usr/bin/nto${ntoarch}-ar
	        CACHE PATH "QNX ar Program" FORCE)

