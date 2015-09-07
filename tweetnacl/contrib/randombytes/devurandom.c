#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* it's really stupid that there isn't a syscall for this */

static int fd = -1;

void randombytes(unsigned char *x,unsigned long long xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

int randombytes_close(void)
{
  int rc = -1;
  if(fd != -1 && close(fd) == 0) {
    fd = -1;
    rc = 0;
  }
  return rc;
}
