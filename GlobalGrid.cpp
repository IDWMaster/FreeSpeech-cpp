#include "GlobalGrid.h"
#include <stdlib.h>
#include <set>
#include <string.h>
#include "crypto.h"
#include "database.h"
#include "cppext/cppext.h"
#include <map>

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
  std::shared_ptr<GlobalGrid::VSocket> socket;
  
  uint64_t challenge[2];
  
  
  uint64_t claimedThumbprint[2]; //The claimed thumbprint of the client.
  bool verified; //Whether or not this Session is client-ID verified
  
  Session(const std::shared_ptr<GlobalGrid::VSocket>& socket,unsigned char* key, unsigned char* claimedThumbprint) {
    memcpy(this->key,key,32);
    this->socket = socket;
    secure_random_bytes(&challenge,16);
    verified = false;
    memcpy(this->claimedThumbprint,claimedThumbprint,16);
  }
  Session(const std::shared_ptr<GlobalGrid::VSocket>& socket) {
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
  std::map<GlobalGrid::Guid,std::weak_ptr<GlobalGrid::VSocket>> routes;
  GGRouter(void* privkey) {
    this->privkey = privkey;
  }
  void NtfyPacket(std::shared_ptr<GlobalGrid::VSocket> socket,unsigned char* packetData, size_t packetLength) {
    printf("Got packet?\n");
    if(sessions.find(socket) == sessions.end()) {
      //We should have an AES key in our packet here encrypted with our public key.
      
      
      //Packet header -- thumbprint (16 bytes) (unverified data element), session key (variable length, encrypted)
      if(packetLength<=16) {
	return;
      }
      void* packet = RSA_Decrypt(privkey,packetData+16,packetLength-16);
      if(packet == 0) { //Decryption failure.
	printf("Houston has another problem\n");
	return;
      }
      unsigned char* buffer;
      size_t sz;
      GlobalGrid::Buffer_Get(packet,&buffer,&sz);
      if(sz>=32) {
	//We have a new Session.
	Session route(socket,buffer,packetData);
	sessions.insert(route);
	//Respond with ACK, which verifies our identity
	//Send challenge to verify remote identity.
	
	char hexprint[33];
	ToHexString((unsigned char*)route.claimedThumbprint,16,hexprint);
	hexprint[32] = 0;
	
	void* remoteKey = DB_FindAuthority(hexprint);
	
	if(remoteKey) {
	  void* challenge = RSA_Encrypt(remoteKey,(unsigned char*)route.challenge,16);
	  unsigned char* challenge_bytes;
	  size_t challenge_size;
	  GlobalGrid::Buffer_Get(challenge,&challenge_bytes,&challenge_size);
	  size_t aligned_challenge = 1+2+challenge_size;
	  aligned_challenge+=16-(aligned_challenge % 16);
	  unsigned char* xmitPacket = new unsigned char[aligned_challenge];
	  memset(xmitPacket,0,aligned_challenge);
	  uint16_t pc_sz = (uint16_t)challenge_size; //TODO: Transmit size of RSA encrypted blob along with actual blob
	  memcpy(xmitPacket+1,&pc_sz,2);
	  memcpy(xmitPacket+1+2,challenge_bytes,challenge_size);
	  for(size_t i = 0;i<aligned_challenge;i+=16) {
	    aes_encrypt(route.key,xmitPacket+i);
	  }
	  socket->Send(xmitPacket,aligned_challenge);
	  delete[] xmitPacket;
	  GlobalGrid::GGObject_Free(challenge);
	}else {
	  //We don't have a remote key. Request it.
	  unsigned char izard[16];
	  memset(izard,0,16);
	  izard[0] = 2;
	  aes_encrypt(route.key,izard);
	  socket->Send(izard,16);
	}
	GlobalGrid::GGObject_Free(packet);
      }else {
	GlobalGrid::GGObject_Free(packet);
      }
    }else {
      //Bind to existing Session.
      if(packetLength % 16 != 0) {
	//Invalid packet.
	return;
      }
      
      Session session = *sessions.find(socket);
      for(size_t i = 0;i<packetLength;i+=16) {
	aes_decrypt(session.key,packetData+i);
      }
      
      switch(*packetData) {
	case 0:
	  //Challenge request
	{
	  //Decrypt challenge
	  uint16_t len;
	  memcpy(&len,packetData+1,2);
	  void* challenge = RSA_Decrypt(privkey,packetData+1+2,len);
	  if(challenge == 0) {
	    return;
	  }
	  unsigned char* challenge_bytes;
	  size_t challenge_sz;
	  
	  GlobalGrid::Buffer_Get(challenge,&challenge_bytes,&challenge_sz);
	  if(challenge_sz != 16) {
	    GlobalGrid::GGObject_Free(challenge);
	    return;
	  }
	  
	  unsigned char response[32];
	  memset(response,0,32);
	  response[0] = 1;
	  memcpy(response+1,challenge_bytes,16);
	  aes_encrypt(session.key,response);
	  aes_encrypt(session.key,response+16);
	  socket->Send(response,32);
	  GlobalGrid::GGObject_Free(challenge);
	  
	  
	}
	  break;
	case 1:
	{
	  //Response to challenge (identity verification)
	  printf("Received response to challenge\n");
	  if(memcmp(session.challenge,packetData+1,16) == 0) {
	    printf("Identity verified.\n");
	  }
	}
	  break;
	case 2:
	{
	  //Request for public encryptionKey.
	  void* key = RSA_Export(privkey,false);
	  unsigned char* key_bytes;
	  size_t key_size;
	  GlobalGrid::Buffer_Get(key,&key_bytes,&key_size);
	  size_t aligned = key_size+1;
	  aligned+=16-(aligned % 16);
	  
	  unsigned char* packet = new unsigned char[aligned];
	  memcpy(packet+1,key_bytes,key_size);
	  packet[0] = 3;
	  
	  for(size_t i = 0;i<aligned;i+=16) {
	    aes_encrypt(session.key,packet+i);
	  }
	  
	  socket->Send(packet,aligned);
	  delete[] packet;
	  GlobalGrid::GGObject_Free(key);
	  
	}
	  break;
	case 3:
	{
	  //Received public encryption key
	  void* key = RSA_Key(packetData+1,packetLength-1);
	  char thumbprint[33];
	  RSA_thumbprint(key,thumbprint);
	  thumbprint[32] = 0;
	  void* obj = DB_FindAuthority(thumbprint);
	  if(obj == 0) {
	    void* keybin = RSA_Export(key,false);
	    unsigned char* cert;
	    size_t cert_len;
	    GlobalGrid::Buffer_Get(keybin,&cert,&cert_len);
	    DB_Insert_Certificate(thumbprint,cert,cert_len,false);
	    GlobalGrid::GGObject_Free(keybin);
	    if(session.verified == false) {
	      //TODO: Send verification request
	      
	      void* challenge = RSA_Encrypt(key,(unsigned char*)session.challenge,16);
	  unsigned char* challenge_bytes;
	  size_t challenge_size;
	  GlobalGrid::Buffer_Get(challenge,&challenge_bytes,&challenge_size);
	  size_t aligned_challenge = 1+challenge_size;
	  aligned_challenge+=16-(aligned_challenge % 16);
	  unsigned char* xmitPacket = new unsigned char[aligned_challenge];
	  memset(xmitPacket,0,aligned_challenge);
	  memcpy(xmitPacket+1,challenge_bytes,challenge_size);
	  for(size_t i = 0;i<aligned_challenge;i+=16) {
	    aes_encrypt(session.key,xmitPacket+i);
	  }
	  socket->Send(xmitPacket,aligned_challenge);
	  delete[] xmitPacket;
	  GlobalGrid::GGObject_Free(challenge);
	    }
	  }else {
	    RSA_Free(obj);
	  }
	}
	  break;
      }
    }
  }
  void Handshake(const std::shared_ptr<GlobalGrid::VSocket>& socket, void* remoteKey) {
    //Remote thumbprint + AES session key
    unsigned char thumbprint[16];
    Session session(socket);
    secure_random_bytes(session.key,32);
    RSA_thumbprint(remoteKey,thumbprint);
    //Encrypt second part of message containing AES session key
    void* buffy = RSA_Encrypt(remoteKey,session.key,32);
    unsigned char* buffy_bytes;
    size_t buffy_size;
    GlobalGrid::Buffer_Get(buffy,&buffy_bytes,&buffy_size); //Be careful. Buffy bytes!
    unsigned char* mander = new unsigned char[16+buffy_size];
    memcpy(mander,thumbprint,16);
    memcpy(mander+16,buffy_bytes,buffy_size);
    socket->Send(mander,16+buffy_size); //Send Charmander into battle.
    sessions.insert(session);
    delete[] mander;
    GlobalGrid::GGObject_Free(buffy);
    
    
  }
};
void GlobalGrid::GlobalGrid_InitiateHandshake(void* connectionManager, std::shared_ptr< GlobalGrid::VSocket > socket, void* remoteKey)
{
((GGRouter*)connectionManager)->Handshake(socket,remoteKey);
}

void GlobalGrid::GlobalGrid_NtfyPacket(void* connectionManager, std::shared_ptr< GlobalGrid::VSocket > socket, unsigned char* packet, size_t packetlength)
{
  ((GGRouter*)connectionManager)->NtfyPacket(socket,packet,packetlength);
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
