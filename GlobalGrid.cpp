#include "GlobalGrid.h"
#include <stdlib.h>
#include <set>
#include <string.h>
#include "crypto.h"
class IDisposable {
public:
  ~IDisposable(){};
};

class Buffer:public IDisposable {
  public:
    size_t len;
    void* data;
  Buffer(size_t len) {
    this->len = len;
    this->data = malloc(len);
  }
  ~Buffer() {
    free(data);
  }
};

void GlobalGrid::Buffer_Get(void* buffer,void** out, size_t* sz)
{
  Buffer* buffy = (Buffer*)buffer;
  *out = buffy->data;
  *sz = buffy->len;
}

void* GlobalGrid::Buffer_Create(size_t sz)
{
  return new Buffer(sz);
}

void GlobalGrid::GGObject_Free(void* obj)
{
  delete (IDisposable*)obj;
}




class Session {
public:
  unsigned char key[32];
  std::weak_ptr<GlobalGrid::VSocket> socket;
  
  uint64_t challenge;
  
  
  uint64_t claimedThumbprint[2]; //The claimed thumbprint of the client.
  bool verified; //Whether or not this Session is client-ID verified
  
  Session(std::weak_ptr<GlobalGrid::VSocket> socket,unsigned char* key, unsigned char* claimedThumbprint) {
    memcpy(this->key,key,32);
    this->socket = socket;
    secure_random_bytes(&challenge,8);
    verified = false;
    memcpy(this->claimedThumbprint,claimedThumbprint,16);
  }
  Session(std::weak_ptr<GlobalGrid::VSocket> socket) {
    this->socket = socket;
    verified = false;
  }
  bool operator<(const Session& other) const {
    return socket<other.socket;
  }
};


class GGRouter:public IDisposable {
public:
  void* privkey;
  std::map<GlobalGrid::Guid,std::shared_ptr<GlobalGrid::ProtocolDriver>> drivers;
  std::set<Session> sessions;
  std::map<GlobalGrid::Guid,std::shared_ptr<GlobalGrid::VSocket>> routes;
  GGRouter(void* privkey) {
    this->privkey = privkey;
  }
  void NtfyPacket(std::shared_ptr<GlobalGrid::VSocket> socket,unsigned char* packetData, size_t packetLength) {
    if(sessions.find(socket) == sessions.end()) {
      //We should have an AES key in our packet here encrypted with our public key.
      
      
      //Packet header -- thumbprint (16 bytes) (unverified data element), session key (variable length, encrypted)
      if(packetLength<=16) {
	return;
      }
      RSA_Decrypt(privkey,packetData+16,packetLength-16);
      
      if(packetLength<=16) {
	return;
      }
      
      
      void* packet = RSA_Decrypt(privkey,packet);
      if(packet == 0) { //Decryption failure.
	return;
      }
      unsigned char* buffer;
      size_t sz;
      GlobalGrid::Buffer_Get(packet,&buffer,&sz);
      if(sz>=32) {
	//We have a new Session.
	Session route(socket,buffer);
	
	sessions.insert(route);
	//Respond with ACK, which verifies our identity
	//Send challenge to verify remote identity.
	unsigned char mander[16];
	memset(mander,0,16);
	memcpy(mander+1,&route.challenge,8);
	aes_encrypt(buffer,mander);
	socket->Send(mander,16);
      }
    }else {
      //We have a packet destined for us. It's our destiny!
      
      if(packetLength % 16 != 0) {
	//Invalid packet.
	return;
      }
      Session session = sessions[socket];
      switch(*packetData) {
	case 0:
	  //Challenge request
	{
	  //Respond to challenge (proving our identity)
	  unsigned char response[32];
	  memset(response,0,32); //Zero out buffer to prevent leakage of sensitive information.
	  RSA_thumbprint(privkey,response+1);
	  response[0] = 1;
	}
	  break;
      }
    }
  }
  
};

void GlobalGrid::GlobalGrid_NtfyPacket(void* connectionManager, std::shared_ptr< GlobalGrid::VSocket > socket, unsigned char* packet, size_t packetlength)
{
  ((GGRouter*)connectionManager)->NtfyPacket(socket,packet,packet,packetlength);
}


void GlobalGrid::GlobalGrid_RegisterProtocolDriver(void* connectionManager, std::shared_ptr< GlobalGrid::ProtocolDriver > driver)
{
  GGRouter* router = (GGRouter*)connectionManager;
  router->drivers[driver->id] = driver;
}


void* GlobalGrid::GlobalGrid_InitRouter(void* encryptionKey)
{
  return new GGRouter(encryptionKey);
}
