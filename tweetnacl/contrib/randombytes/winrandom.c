#include <windows.h>
#include <WinCrypt.h>

#define NCP ((HCRYPTPROV) 0)

HCRYPTPROV hProvider = NCP;

void randombytes(unsigned char *x,unsigned long long xlen)
{
  unsigned i;
  BOOL ret;

  if (hProvider == NCP) {
    for(;;) {
      ret = CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
      if (ret != FALSE) break;
      Sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = (unsigned) xlen; else i = 1048576;

    ret = CryptGenRandom(hProvider, i, x);
    if (ret == FALSE) {
      Sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

int randombytes_close(void)
{
  int rc = -1;
  if((hProvider != NCP) && (CryptReleaseContext(hProvider, 0) != FALSE)) {
    hProvider = NCP;
    rc = 0;
  }
  return rc;
}
