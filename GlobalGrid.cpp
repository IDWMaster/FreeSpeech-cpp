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

#include "GlobalGrid.h"
#include <stdlib.h>
#include <set>
#include <string.h>
#include "crypto.h"
#include "database.h"
#include "cppext/cppext.h"
#include <map>
#include <chrono>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
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

void* MMAP_Map(const char* filename, size_t& maplen, int& fd) {
  struct stat us;
  if(!stat(filename,&us)) {
    //Map in file
    fd = open(filename,O_RDWR);
    maplen = us.st_size;
    return mmap(0,us.st_size,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
  }else {
    //Create file, and map
    maplen = 1024*1024;
    fd = open(filename,O_RDWR | O_CREAT,S_IRUSR | S_IWUSR);
    fallocate(fd,0,0,maplen);
    return mmap(0,maplen,PROT_READ | PROT_WRITE,MAP_SHARED,fd,0);
  }
}
void* MMAP_Realloc(void* mapping, int fd, size_t oldSize, size_t newSize) {
  
  fallocate(fd,0,0,newSize);
  return mremap(mapping,oldSize,newSize,MREMAP_MAYMOVE);
}
class KnownHost {
public:
  GlobalGrid::Guid thumbprint;
  size_t mapped_offset; //Offset into memory-mapped file
  KnownHost(const GlobalGrid::Guid& thumbprint) {
    this->thumbprint = thumbprint;
  }
  bool operator<(const KnownHost& other) const {
    return thumbprint<other.thumbprint;
  }
  
};

class GGRouter:public IDisposable {
public:
  void* privkey;
  std::map<GlobalGrid::Guid,std::shared_ptr<GlobalGrid::ProtocolDriver>> drivers;
  std::set<Session> sessions; //Active list of sessions (TODO these have to be garbage-collected somehow).
  std::map<std::chrono::steady_clock::time_point,std::shared_ptr<GlobalGrid::VSocket>> socketActivity; //Time since a given socket has received valid data
  std::map<std::shared_ptr<GlobalGrid::VSocket>,std::chrono::steady_clock::time_point> socketActivity_reverse; //Reverse lookup for time intervals
  std::map<GlobalGrid::Guid,std::weak_ptr<GlobalGrid::VSocket>> routes; //Known routes
  std::set<KnownHost> knownHosts_index;
  int knownpeers_fd;
  GlobalGrid::Guid localGuid;
  size_t knownPeers_size;
  unsigned char* knownPeers; //Known peers
  void balance() {
    //TODO: Lukeup known VSockets in database
    size_t handcount = 0;
    for(auto bot = knownHosts_index.begin();bot!= knownHosts_index.end();bot++) {
      
      KnownHost host = *bot;
      if(routes.find(host.thumbprint) == routes.end()) {
	handcount++;
	uint32_t len;
	memcpy(&len,knownPeers+host.mapped_offset,4);
	std::shared_ptr<GlobalGrid::VSocket> dsocket = Deserialize(knownPeers+host.mapped_offset+4+16,len);
	char mander[(16*2)+1];
	ToHexString((unsigned char*)host.thumbprint.value,16,mander);
	printf("Find auth %s\n",mander);
	void* key = DB_FindAuthority(mander);
	Handshake(dsocket,key);
	RSA_Free(key);
      }
    }
    printf("Loaded %i VSockets from local cache.\n",(int)handcount);
  }
  std::shared_ptr<GlobalGrid::VSocket> Deserialize(unsigned char* bytes, size_t len) {
    return drivers[GlobalGrid::Guid(bytes)]->Deserialize(bytes+16,len-16);
    
  }
  void* Serialize(const std::shared_ptr<GlobalGrid::VSocket>& s) {
    void* buffer = s->Serialize();
    unsigned char* bytes;
    size_t len;
    GlobalGrid::Buffer_Get(buffer,&bytes,&len);
    void* retval = GlobalGrid::Buffer_Create(16+len);
    unsigned char* ret_bytes;
    size_t ret_len;
    GlobalGrid::Buffer_Get(retval,&ret_bytes,&ret_len);
    s->GetProtocolID(ret_bytes);
    memcpy(ret_bytes+16,bytes,len);
    GlobalGrid::GGObject_Free(buffer);
    return retval;
  }
  
  void Insert_Peer(const std::shared_ptr<GlobalGrid::VSocket>& s, const uint64_t* thumbprint) {
    if(knownHosts_index.find(KnownHost(thumbprint)) == knownHosts_index.end()) {
      void* buffy = Serialize(s);
      unsigned char* bytes;
      size_t len;
      GlobalGrid::Buffer_Get(buffy,&bytes,&len);
      size_t outputLen = 4+16+len;
      void* output_buffer = GlobalGrid::Buffer_Create(outputLen);
      unsigned char* obytes;
      size_t olen;
      GlobalGrid::Buffer_Get(output_buffer,&obytes,&olen);
      uint32_t len_aligned = (uint32_t)len;
      memcpy(obytes,&len_aligned,4);
      memcpy(obytes+4,thumbprint,16);
      memcpy(obytes+4+16,bytes,len);
      GlobalGrid::GGObject_Free(buffy);
      
      uint64_t end;
      memcpy(&end,knownPeers,8);
      if(end == 0) {
	end = 8;
	memcpy(knownPeers,&end,8);
      }
      
      memcpy(knownPeers+end,obytes,outputLen);
      KnownHost host(thumbprint);
      host.mapped_offset = end;
      knownHosts_index.insert(host);
      end+=outputLen;
      memcpy(knownPeers,&end,8);
      GlobalGrid::GGObject_Free(output_buffer);
      
    }else {
      printf("TODO: Replace VSocket in file.");
      KnownHost host = *knownHosts_index.find(KnownHost(thumbprint));
      knownHosts_index.clear();
      //Erase entry at mapped_offset and insert at end
      uint32_t entry_vsocket_len;
      uint64_t endPos;
      memcpy(&endPos,knownPeers,8);
      memcpy(&entry_vsocket_len,knownPeers+host.mapped_offset,4);
      void* copySrc = knownPeers+host.mapped_offset+4+16+entry_vsocket_len;
      void* copyEnd = knownPeers+endPos;
      memmove(knownPeers+host.mapped_offset,copySrc,(size_t)copyEnd-(size_t)copySrc);
      endPos-=4+16+entry_vsocket_len;
      memcpy(knownPeers,&endPos,8);
      peerparse();
      Insert_Peer(s,thumbprint);
    }
  }
  void GC() {
    
    
    uint64_t timeout_seconds = 120;
    
    while(socketActivity.size()) {
      auto bot = socketActivity.begin();
      if(std::chrono::steady_clock::now()-bot->first>std::chrono::seconds(timeout_seconds)) {
	std::shared_ptr<GlobalGrid::VSocket> ms = bot->second;
	auto foundSession = sessions.find(Session(ms));
	if(foundSession != sessions.end()) {
	  Session s = *foundSession;
	  sessions.erase(s);
	  socketActivity.erase(bot);
	  socketActivity_reverse.erase(socketActivity_reverse.find(s.socket));
	}
      }else {
	break;
      }
      
    }
    
    if(sessions.size() == 0) {
      balance();
    }
  }
  void RefreshSocket(const std::shared_ptr<GlobalGrid::VSocket>& s) {
    if(socketActivity_reverse.find(s) != socketActivity_reverse.end()) {
      socketActivity.erase(socketActivity.find(socketActivity_reverse[s]));
    }else {
      GC();
    }
    std::chrono::steady_clock::time_point tp = std::chrono::steady_clock::now();
    socketActivity[tp] = s;
    socketActivity_reverse[s] = tp;
  }
  
  void peerparse() {
    //Read database
    uint64_t endEger;
    memcpy(&endEger,knownPeers,8);
    unsigned char* end = knownPeers+endEger;
    unsigned char* ptr = knownPeers+8;
    while((size_t)ptr<(size_t)end) {
      unsigned char* start = ptr;
      uint32_t len;
      memcpy(&len,ptr,4);
      KnownHost host(ptr+4);
      
      host.mapped_offset = (size_t)start-(size_t)knownPeers;
      ptr+=4+16+len;
      knownHosts_index.insert(host);
    }
  }
  GGRouter(void* privkey) {
    
    knownPeers = (unsigned char*)MMAP_Map("known_hosts",knownPeers_size,knownpeers_fd);
    this->privkey = privkey;
    RSA_thumbprint(privkey,(unsigned char*)localGuid.value);
    //Read database
    peerparse();
  }
  
  //Use the DHT Kademlia algorithm to find the best node that we're aware of.
  //This works using the following method:
  //Find the peer with the lowest distance between the key, and the peer ID (distance is the result of (key ^ peer GUID))
  //Return the peer which was found.
  //In our case; we modify our method such that it can return multiple peers, 
  size_t FindBestPeersForHash(const GlobalGrid::Guid& lukeup, GlobalGrid::Guid* peerlist, size_t numPeers) {
    size_t numLeft = sessions.size();
    uint64_t distance[2]; //Current distance
    distance[0] = -1;
    distance[1] = -1;
    size_t currentPeer = 0;
    size_t found = 0;
    size_t foundPeers = 0;
    for(auto bot = sessions.begin();bot != sessions.end();bot++) {
      //Compute distance
      uint64_t cdist[2];
      cdist[0] = distance[0] ^ lukeup.value[0];
      cdist[1] = distance[1] ^ lukeup.value[1];
      
      //NOTE: We really only need to compare the first 64-bits
      //The chances of any two being the same are astronomically low.
      if(cdist[0]<distance[0]) {
      
      
	if((*bot).verified) {
	  distance[0] = cdist[0];
	  distance[1] = cdist[1];
	  peerlist[currentPeer] = GlobalGrid::Guid(bot->claimedThumbprint);
	  currentPeer = (currentPeer + 1) % numPeers;
	  if(foundPeers<numPeers) {
	    foundPeers++;
	  }
	}
      
      }
    }
    return foundPeers;
  }
  
  void SendChallenge(void* remoteKey, Session& route, const std::shared_ptr<GlobalGrid::VSocket>& socket) {
    //Construct challenge
    void* challenge = RSA_Encrypt(remoteKey,(unsigned char*)route.challenge,16);
	  unsigned char* challenge_bytes;
	  size_t challenge_size;
	  GlobalGrid::Buffer_Get(challenge,&challenge_bytes,&challenge_size);
	  size_t aligned_challenge = 1+2+challenge_size;
	  aligned_challenge+=16-(aligned_challenge % 16);
	  unsigned char* xmitPacket = new unsigned char[aligned_challenge];
	  memset(xmitPacket,0,aligned_challenge);
	  uint16_t pc_sz = (uint16_t)challenge_size;
	  memcpy(xmitPacket+1,&pc_sz,2);
	  memcpy(xmitPacket+1+2,challenge_bytes,challenge_size);
	  aes_encrypt_packet(route.key,(uint64_t*)xmitPacket,aligned_challenge);
	  
	  socket->Send(xmitPacket,aligned_challenge);
	  delete[] xmitPacket;
	  GlobalGrid::GGObject_Free(challenge);
  }
  void aes_encrypt_packet(void* key,uint64_t* packet, size_t alignedSize) {
    unsigned char* mander = (unsigned char*)packet;
    aes_encrypt(key,packet);
    for(size_t i = 16;i<alignedSize;i+=16) {
      //XOR with previous ciphertext block
      ((uint64_t*)(mander+i))[0] ^= ((uint64_t*)(mander+i-16))[0];
      ((uint64_t*)(mander+i))[1] ^= ((uint64_t*)(mander+i-16))[1];
      aes_encrypt(key,mander+i);
    }
  }
  void aes_decrypt_packet(void* key, uint64_t* packet, size_t size) {
    if(size % 16) {
      return;
    }
    unsigned char* mander = (unsigned char*)packet;
    for(size_t i = size-16;i>=16;i-=16) {
      aes_decrypt(key,mander+i);
      ((uint64_t*)(mander+i))[0] ^= ((uint64_t*)(mander+i-16))[0];
      ((uint64_t*)(mander+i))[1] ^= ((uint64_t*)(mander+i-16))[1];
    }
    aes_decrypt(key,packet);
    
  }
  
  void NtfyPacket(std::shared_ptr<GlobalGrid::VSocket> socket,unsigned char* packetData, size_t packetLength) {
   printf("Got packet?\n");
    if((size_t)packetData % 8) {
      throw "Driver error. Packets must be aligned on 64-bit boundaries.";
    }
    if(sessions.find(socket) == sessions.end()) {
      printf("Session not found.\n");
      //We should have an AES key in our packet here encrypted with our public key.
      
      
      //Packet header -- thumbprint (16 bytes) (unverified data element), session key (variable length, encrypted)
      if(packetLength<=16) {
	return;
      }
      void* packet = RSA_Decrypt(privkey,packetData+16,packetLength-16);
      if(packet == 0) { //Decryption failure.
	printf("Failed to decrypt initial packet.");
	sessions.erase(socket);
	return;
      }
      unsigned char* buffer;
      size_t sz;
      GlobalGrid::Buffer_Get(packet,&buffer,&sz);
      if(sz>=32) {
	printf("Got new session\n");
	//We have a new Session.
	Session route(socket,buffer,packetData);
	routes[route.claimedThumbprint] = route.socket;
	sessions.insert(route);
	//Respond with ACK, which verifies our identity
	//Send challenge to verify remote identity.
	
	char hexprint[33];
	ToHexString((unsigned char*)route.claimedThumbprint,16,hexprint);
	hexprint[32] = 0;
	
	void* remoteKey = DB_FindAuthority(hexprint);
	
	if(remoteKey) {
	  SendChallenge(remoteKey,route,socket);
	  RSA_Free(remoteKey);
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
      printf("Got data packet\n");
      //Bind to existing Session.
      if(packetLength % 16 != 0) {
	//Invalid packet.
	printf("Invalid packet length. Got %i, which was not aligned to 16 bytes.\n",(int)packetLength);
	return;
      }
      if((size_t)packetData % 16) {
	printf("WARNING: Unaligned memory address\n");
      }
      
      Session session = *sessions.find(socket);
      aes_decrypt_packet(session.key,(uint64_t*)packetData,packetLength);
   
      switch(*packetData) {
	case 0:
	  //Challenge request
	{
	  //Decrypt challenge
	  uint16_t len;
	  memcpy(&len,packetData+1,2);
	  if(len>packetLength-1-2) {
	    return;
	  }
	  void* challenge = RSA_Decrypt(privkey,packetData+1+2,len);
	  if(challenge == 0) {
	    //TODO: Unable to decrypt? Are we using the wrong private key; or public key during transmission?
	    printf("Unable to decrypt challenge (challenge size == %i)\n",(int)len);
	    return;
	  }
	  unsigned char* challenge_bytes;
	  size_t challenge_sz;
	  
	  GlobalGrid::Buffer_Get(challenge,&challenge_bytes,&challenge_sz);
	  if(challenge_sz != 16) {
	    GlobalGrid::GGObject_Free(challenge);
	    return;
	  }
	  
	  uint64_t response_buffer[4];
	  unsigned char* response = (unsigned char*)response_buffer;
	  memset(response,0,32);
	  response[0] = 1;
	  memcpy(response+1,challenge_bytes,16);
	  aes_encrypt_packet(session.key,response_buffer,32);
	  socket->Send(response,32);
	  GlobalGrid::GGObject_Free(challenge);
	  
	  printf("Sent challenge response\n");
	  
	}
	  break;
	case 1:
	{
	  //Response to challenge (identity verification)
	  if(memcmp(session.challenge,packetData+1,16) == 0) {
	    session.verified = true;
	    sessions.erase(session);
	    sessions.insert(session);
	    printf("Identity verified.\n");
	    Insert_Peer(session.socket,session.claimedThumbprint);
	  }else {
	    printf("Identity verification failed.\n");
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
	  uint16_t keySize = (uint16_t)key_size;
	  size_t aligned = 1+2+key_size;
	  aligned+=16-(aligned % 16);
	  
	  unsigned char* packet = (unsigned char*)new uint64_t[aligned/8];
	  packet[0] = 3;
	  memcpy(packet+1,&keySize,2);
	  memcpy(packet+1+2,key_bytes,key_size);
	  aes_encrypt_packet(session.key,(uint64_t*)packet,aligned);
	  
	  socket->Send(packet,aligned);	  

	  delete[] (uint64_t*)packet;
	  GlobalGrid::GGObject_Free(key);
	  
	}
	  break;
	case 3:
	{
	  //Received public encryption key
	  uint16_t keyLen;
	  memcpy(&keyLen,packetData+1,2);
	  if(keyLen>packetLength-1-2) {
	    printf("Illegal key length\n");
	    return;
	  }
	  void* key = RSA_Key(packetData+1+2,keyLen);
	  if(key == 0) {
	    printf("ERROR: Invalid encryption key.\n");
	    return;
	  }
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
	      SendChallenge(key,session,socket);
	    }
	  }else {
	    RSA_Free(obj);
	  }
	}
	  break;
	case 4:
	{
	  //Route packet
	  packetData++;
	  unsigned char ttl = *packetData;
	  packetData++;
	  
	  //Intended destination
	  GlobalGrid::Guid dest;
	  memcpy(dest.value,packetData,16);
	  packetData+=16;
	  GlobalGrid::Guid localThumbprint;
	  RSA_thumbprint(privkey,(unsigned char*)localThumbprint.value);
	  uint32_t packetSize;
	  memcpy(&packetSize,packetData,4);
	  packetData+=16;
	  if(dest == localGuid) {
	    printf("TODO: Packet destined for ourselves\n");
	    return;
	  }
	  SendPacket(packetData,packetSize,ttl,dest,session.claimedThumbprint);
	  
	}
	  break;
	default:
	  printf("Unknown OPCODE\n");
      }
    }
  }
  void SendPacket(unsigned char* packet, size_t sz, unsigned char ttl, const GlobalGrid::Guid& dest, const GlobalGrid::Guid& origin) {
    if(sessions.size() == 0) {
      //No active connections. Perform scan.
      balance();
    }
        //TODO: Find best route
	    std::shared_ptr<GlobalGrid::VSocket> sock = routes[dest].lock();
	    if(sock && (sessions.find(sock) != sessions.end())) {
	      auto s = sessions.find(sock);
	      if(s->verified) {
		SendPacketRouted(*s,packet,sz,ttl-1,dest);
		return;
	      }
	    }
	  
	  
	  //Find best routes
	  GlobalGrid::Guid candidateRoute;
	  size_t numRoutes = FindBestPeersForHash(dest,&candidateRoute,1); //NOTE: If we're the one sending the packet, we may want to route along more than one path. If we're relaying a packet, we should only care about the next hop in the chain.
	  
	  if(numRoutes && (origin != candidateRoute)) {
	    
	    std::shared_ptr<GlobalGrid::VSocket> sock = routes[candidateRoute].lock();
	    if(!sock) {
	      printf("No route to host\n");
	    }
	    if(sock && (sessions.find(sock) != sessions.end())) {
	      
	      SendPacketRouted(*sessions.find(sock),packet,sz,ttl-1,dest);
	    }
	    
	  }else {
	    printf("No route to host\n");
	  }
  }
  void SendPacketRouted(const Session& route, unsigned char* packet, size_t sz, unsigned char ttl, const GlobalGrid::Guid& dest) {
   size_t pSize = 1+1+16+4+sz;
   pSize+=(16-(pSize % 16));
   unsigned char* mander = (unsigned char*)new uint64_t[pSize/8];
   *mander = 4;
   *(mander+1) = ttl;
   memcpy(mander+1+1,dest.value,16);
   uint32_t ss = sz;
   memcpy(mander+1+1+16,&ss,4);
   memcpy(mander+1+1+16+4,packet,sz);
   aes_encrypt_packet((void*)route.key,(uint64_t*)mander,pSize);
   
   route.socket->Send(mander,pSize);
   delete[] (uint64_t*)mander;
  }
  void Handshake(const std::shared_ptr<GlobalGrid::VSocket>& socket, void* remoteKey) {
    
    Session session(socket);
    session.verified = true; //If they can send back a response (properly encoded; that is); we know that we're verified
    uint64_t thumbprint[2];
    RSA_thumbprint(remoteKey,(unsigned char*)thumbprint);
    session.claimedThumbprint[0] = thumbprint[0];
    session.claimedThumbprint[1] = thumbprint[1];
    Insert_Peer(socket,thumbprint);
    secure_random_bytes(session.key,32);
    //Encrypt second part of message containing AES session key
    void* buffy = RSA_Encrypt(remoteKey,session.key,32);
    unsigned char* buffy_bytes;
    size_t buffy_size;
    GlobalGrid::Buffer_Get(buffy,&buffy_bytes,&buffy_size); //Be careful. Buffy bytes!
    unsigned char* mander = new unsigned char[16+buffy_size];
    memcpy(mander,localGuid.value,16);
    memcpy(mander+16,buffy_bytes,buffy_size);
    socket->Send(mander,16+buffy_size); //Send Charmander into battle.
    routes[thumbprint] = socket;
    sessions.insert(session);
    delete[] mander;
    GlobalGrid::GGObject_Free(buffy);
    
    
  }
};

void GlobalGrid::GlobalGrid_SendPacket(void* connectionManager, const GlobalGrid::Guid& dest, unsigned char* data, size_t sz)
{
  GGRouter* conman = (GGRouter*)connectionManager;
  conman->SendPacket(data,sz,30,dest,conman->localGuid);
}

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
