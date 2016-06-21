/*

 This file is part of the GlobalGrid Protocol Suite.

    GlobalGrid is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GlobalGrid is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GlobalGrid.  If not, see <http://www.gnu.org/licenses/>.
 * */

#include "cppext/cppext.h"
#include <fcntl.h>
#include "database.h"
#include "crypto.h"
#include <thread>
#include "ip.h"
#include <unistd.h>







int main(int argc, char** argv) {

  
  
  





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

if(argc>1) {
  if(strcmp(argv[1],"export") == 0) {
    //Export public key
    void* buffy = RSA_Export(privkey,false);
    unsigned char* mander;
    size_t sz;
    GlobalGrid::Buffer_Get(buffy,&mander,&sz);
    write(STDOUT_FILENO,mander,sz);
    return 0;
  }else {
    if(strcmp(argv[1],"import") == 0) {
      unsigned char mander[4096];
      
      int len = 0;
      int cl;
      while((cl = read(STDIN_FILENO,mander+len,4096-len))>0) {
	len+=cl;
	printf("Read\n");
      }
      void* key = RSA_Key(mander,len);
      if(key == 0) {
	printf("Invalid key. Cannot import.\n");
	return -1;
      }
       char thumbprint[33];
  thumbprint[32] = 0;
  RSA_thumbprint(key,thumbprint);
  DB_Insert_Certificate(thumbprint,mander,len,false);
  printf("Successfully imported key with thumbprint %s\n",thumbprint);
  
      return 0;
    }
  }
}


char thumbprint[33];
thumbprint[32] = 0;
RSA_thumbprint(privkey,thumbprint);
printf("Your private key thumbprint is %s\n",thumbprint);
void* router = GlobalGrid::GlobalGrid_InitRouter(privkey);




printf("Registering IP protocol driver with system....\n");
System::Net::IPEndpoint routerBinding;
routerBinding.ip = "::";
routerBinding.port = 0;
if(argc>1) {
  routerBinding.ip = argv[4];
  routerBinding.port = atoi(argv[5]);
}
std::shared_ptr<IPProto::IIPDriver> deriver = IPProto::CreateDriver(router,routerBinding);
GlobalGrid::GlobalGrid_RegisterProtocolDriver(router,deriver);
void* locksock = deriver->SerializeLocalSocket();

unsigned char* socket_data;
size_t sock_len;
GlobalGrid::Buffer_Get(locksock,&socket_data,&sock_len);
uint16_t portno;
memcpy(&portno,socket_data+16,2);
printf("Protocol driver active and registered (port %i)\n",(int)portno);


//TODO: Server is listening on appropriate port, as verified by netstat -l.
//Client must not be sending handshake appopriately (or server receive loop isn't working).
//Connect to specified endpoint
if(argc>1) {
  System::Net::IPEndpoint ep;
  ep.ip = argv[1];
  ep.port = atoi(argv[2]);
  const char* thumbprint = argv[3];
  //Connect to remote endpoint.
  void* key = DB_FindAuthority(thumbprint);
  if(key == 0) {
    printf("ERR: Unable to find authority figure.\n");
    abort();
  }
  GlobalGrid::GlobalGrid_InitiateHandshake(router,deriver->MakeSocket(ep),key);
  RSA_Free(key);
}


unsigned char izard[16];
memset(izard,0,16);
GlobalGrid::GlobalGrid_SendPacket(router,izard,izard,1);

    char mander[256];
auto messenger = System::MakeQueue([&](std::shared_ptr<System::Message> msg){
  unsigned char pingmsg = 0;
  GlobalGrid::Guid converted;
  FromHexString(mander,(unsigned char*)converted.value,16*2);
  GlobalGrid::GlobalGrid_SendPacket(router,converted,&pingmsg,1);
    printf("PING %s\n",mander);
});

std::thread m([&](){
  
  while(true) {
    int br = read(0,mander,256);
    if(br <=0) {
      break;
    }
    mander[br] = 0;
    messenger->Post(0);
  }
});

m.detach();


//Local peer discovery
System::Net::IPEndpoint ep;
ep.ip = "::";
ep.port = 7718;
std::shared_ptr<System::Net::UDPSocket> multicastAnnouncer = System::Net::CreateUDPSocket(ep);
multicastAnnouncer->JoinMulticastGroup("ff6e::9877:2");
void* pubkey_buffer = RSA_Export(privkey,false);
unsigned char* pubkey_bytes;
size_t pubkey_size;
GlobalGrid::Buffer_Get(pubkey_buffer,&pubkey_bytes,&pubkey_size);

unsigned char _recvBuffer[4096];
unsigned char* recvBuffer = _recvBuffer;
std::shared_ptr<System::Net::UDPCallback> cb = System::Net::F2UDPCB([&](const System::Net::UDPCallback& results){
  printf("Received multicast packet len = %i\n",(int)results.outlen);
  
  switch(recvBuffer[0]) {
    case 0:
    {
      printf("Ident request\n");
      //Ident request
      unsigned char* response = new unsigned char[1+pubkey_size];
      response[0] = 1;
      memcpy(response+1,pubkey_bytes,pubkey_size);
      multicastAnnouncer->Send(response,pubkey_size,results.receivedFrom);
    }
      break;
    case 1:
    {
      if(memcmp(recvBuffer+1,pubkey_bytes,pubkey_size) == 0) {
	goto velociraptor;
      }
      if(results.outlen<2) {
	goto velociraptor; //Back pain?
      }
      //Found peer. Try to shake hands with it, and import the key (if not already in database).
      char acter[(16*2)+1]; //Remember to stay in character
      void* key = RSA_Key(recvBuffer+1,results.outlen-1);
      if(key == 0) {
	printf("Error. Invalid key.\n");
	goto velociraptor;
      }
      RSA_thumbprint(key,acter); //We have to be a good actor
      
      void* foundkey = DB_FindAuthority(acter);
      if(foundkey) {
	RSA_Free(foundkey);
      }else {
        void* key_bytes = RSA_Export(key,false);
	unsigned char* buffy_bytes; //Be careful. Buffy bytes!
	size_t buffy_size;
	GlobalGrid::Buffer_Get(key_bytes,&buffy_bytes,&buffy_size);
	DB_Insert_Certificate(acter,buffy_bytes,buffy_size,false);
	GlobalGrid::GGObject_Free(key_bytes);
      }
      //Shake hands with remote peer.
      GlobalGrid::GlobalGrid_InitiateHandshake(router,deriver->MakeSocket(results.receivedFrom),key);
      RSA_Free(key);
    }
      break;
  }
  velociraptor:
  multicastAnnouncer->Receive(recvBuffer,4096,cb);
});
unsigned char announcement[1];
announcement[0] = 0;
multicastAnnouncer->Receive(recvBuffer,4096,cb);
System::Net::IPEndpoint dest;
dest.ip = "ff6e::9877:2";
dest.port = 7718;
multicastAnnouncer->Send(announcement,1,dest);

System::Enter();

return 0;
}
