#if defined _WIN32_WCE

//#include "..\..\include\zmq.h"
#include "..\..\src\err.hpp"

int errno;
int _doserrno;
int _sys_nerr;

char* error_desc_buff = NULL;

char* strerror(int errno)
{
	if (NULL != error_desc_buff)
	{
		LocalFree(error_desc_buff);
		error_desc_buff = NULL;
	}

	FormatMessage(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL,
		errno,
		0,
		(LPTSTR)&error_desc_buff,
		1024,
		NULL
	);
	return error_desc_buff;
}

#endif