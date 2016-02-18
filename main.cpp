#include "cppext/cppext.h"
#include <fcntl.h>
#include "database.h"
#include "crypto.h"



int main(int argc, char** argv) {
printf("======================================\n");
printf("Free Speech Project\n");
printf("======================================\n");


void* privkey = 0;

bool(*fptr)(void*,unsigned char*,size_t);


void* thisptr = System::ABI::C([&](unsigned char* data, size_t len){
    privkey = RSA_Key(data,len);
    return false;
},fptr);
DB_EnumPrivateKeys(0,fptr);

if(privkey == 0) {
  printf("Generating 4096-bit RSA key. This may take a while....\n");
  privkey = RSA_GenKey(4096);
  char thumbprint[33];
  RSA_thumbprint(privkey,thumbprint);
  unsigned char* cert;
  size_t certlen;
  RSA_Export(privkey,true,&cert,&certlen);
  DB_Insert_Certificate(thumbprint,cert,certlen);
  RSA_Free_Buffer(cert);
}

return 0;
}
