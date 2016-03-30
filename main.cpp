#include "cppext/cppext.h"
#include <fcntl.h>
#include "database.h"
#include "crypto.h"

#include "ip.h"

int main(int argc, char** argv) {
printf("======================================\n");
printf("Free Speech Project -- System Demon\n");
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
  void* buffy = RSA_Export(privkey,true);
  GlobalGrid::Buffer_Get(buffy,(void**)&cert,&certlen);
  printf("Generated certificate taking %i bytes\n",(int)certlen);
  DB_Insert_Certificate(thumbprint,cert,certlen,true);
  GlobalGrid::GGObject_Free(buffy);
}

char thumbprint[33];
thumbprint[32] = 0;
RSA_thumbprint(privkey,thumbprint);
printf("Your private key thumbprint is %s\n",thumbprint);
void* router = GlobalGrid::GlobalGrid_InitRouter(privkey);
printf("Registering IP protocol driver with system....\n");
std::shared_ptr<GlobalGrid::ProtocolDriver> deriver = IPProto::CreateDriver(router);
void* locksock = deriver->SerializeLocalSocket();

unsigned char* socket_data;
size_t sock_len;
GlobalGrid::Buffer_Get(locksock,&socket_data,&sock_len);
uint16_t portno;
memcpy(&portno,socket_data+16,2);
printf("Protocol driver active and registered (port %i)\n",(int)portno);

System::Enter();

return 0;
}
