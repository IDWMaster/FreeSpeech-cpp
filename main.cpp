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
    if(privkey == 0) {
      printf("Unable to decode private key with size %i.\n",(int)len);
      abort();
    }
    return false;
},fptr);
DB_EnumPrivateKeys(thisptr,fptr);

if(privkey == 0) {
  printf("Generating 4096-bit RSA key. This may take a while....\n");
  privkey = RSA_GenKey(4096);
  char thumbprint[33];
  thumbprint[32] = 0;
  RSA_thumbprint(privkey,thumbprint);
  unsigned char* cert;
  size_t certlen;
  RSA_Export(privkey,true,&cert,&certlen);
  printf("Generated certificate taking %i bytes\n",(int)certlen);
  DB_Insert_Certificate(thumbprint,cert,certlen,true);
  RSA_Free_Buffer(cert);
}

char thumbprint[33];
thumbprint[32] = 0;
RSA_thumbprint(privkey,thumbprint);
printf("Your private key thumbprint is %s\n",thumbprint);

return 0;
}
