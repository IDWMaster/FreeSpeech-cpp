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


#include "ip.h"
#include "crypto.h"
#include "cppext/cppext.h"
#include <map>
#include <netinet/in.h>
#include <libgupnp/gupnp.h>

class IPSocket:public GlobalGrid::VSocket {
public:
  System::Net::IPEndpoint ep;
  std::shared_ptr<System::Net::UDPSocket> sock;
  uint64_t protoID[2];
  IPSocket(const std::shared_ptr<System::Net::UDPSocket>& sock, uint64_t* protoID) {
    this->sock = sock;
    this->protoID[0] = protoID[0];
    this->protoID[1] = protoID[1];
    printf("New socket\n");
  }
  void* Serialize() {
    void* retval = GlobalGrid::Buffer_Create(16+2);
    unsigned char* mander;
    size_t sz;
    GlobalGrid::Buffer_Get(retval,&mander,&sz);
    memcpy(mander,ep.ip.raw,16);
    memcpy(mander+16,&ep.port,2);
    return retval;
  }
void GetProtocolID(void* outbuff) {
  memcpy(outbuff,protoID,16);
}
  void Send(const void* data, size_t sz) {
    sock->Send(data,sz,ep);
  }
  ~IPSocket() {
    printf("Socket disposed\n");
  }
};

class IPDriver:public IPProto::IIPDriver {
public:
  std::shared_ptr<System::Net::UDPSocket> sock;
  std::map<System::Net::IPEndpoint,std::weak_ptr<IPSocket>> socketMappings;
  IPDriver(const System::Net::IPEndpoint& ep) {
    
    
    
    FromHexString("452566E212031284966AB354F7F6CA04",(unsigned char*)id.value,2*16);
    sock = System::Net::CreateUDPSocket(ep); //Put a sock in itself.
    //TODO: Map UPnP port
    
  
  }
  
  std::shared_ptr< GlobalGrid::VSocket > Deserialize(unsigned char* buffer, size_t bufflen) {
    if(bufflen>=16+2) {
      std::shared_ptr<IPSocket> retval = std::make_shared<IPSocket>(sock,id.value);
      memcpy(retval->ep.ip.raw,buffer,16);
      memcpy(&(retval->ep.port),buffer+16,2);
      socketMappings[retval->ep] = retval;
      return retval;
    }else {
      return 0;
    }
  }
std::shared_ptr< GlobalGrid::VSocket > MakeSocket(const System::Net::IPEndpoint& ep) {
  std::shared_ptr<IPSocket> retval = std::make_shared<IPSocket>(sock,id.value);
  retval->ep = ep;
  socketMappings[ep] = retval;
  System::Net::IPEndpoint mp;
  mp.ip = ep.ip;
  mp.port = ep.port;
  /*if(socketMappings.find(mp) == socketMappings.end()) {
    abort();
  }*/
  return retval;
}
  void* SerializeLocalSocket() {
    void* buffy = GlobalGrid::Buffer_Create(16+2);
    unsigned char* mander;
    size_t outsz;
    GlobalGrid::Buffer_Get(buffy,(void**)&mander,&outsz);
    System::Net::IPEndpoint ep;
    sock->GetLocalEndpoint(ep);
    memcpy(mander,ep.ip.raw,16);
    memcpy(mander+16,&ep.port,2);
    return buffy;
  }

~IPDriver() {
  
}
};





std::shared_ptr< IPProto::IIPDriver > IPProto::CreateDriver(void* connectionManager, const System::Net::IPEndpoint& ep)
{ std::shared_ptr<IPDriver> retval = std::make_shared<IPDriver>(ep);
  unsigned char* buffy = (unsigned char*)new uint64_t[512]; //4KB buffer aligned to 64-bits
  std::shared_ptr<System::Net::UDPCallback>* cb = new std::shared_ptr<System::Net::UDPCallback>();
  printf("IP layer -- INIT LISTEN\n");
  *cb = System::Net::F2UDPCB([=](const System::Net::UDPCallback& results){
    
   printf("IP LAYER -- Packet received\n");
    std::shared_ptr<IPSocket> s = retval->socketMappings[results.receivedFrom].lock();
    if(!s) {
      s = std::make_shared<IPSocket>(retval->sock,retval->id.value);
      s->ep = results.receivedFrom;
      retval->socketMappings[results.receivedFrom] = s;
    }
   char ipaddr[INET6_ADDRSTRLEN];
   results.receivedFrom.ip.ToString(ipaddr);
    GlobalGrid::GlobalGrid_NtfyPacket(connectionManager,s,(unsigned char*)buffy,results.outlen);
    printf("IP LAYER -- Waiting for packet\n");
    retval->sock->Receive(buffy,512*8,*cb);
    //TODO: Delete cb AND buffy on destruction of protocol driver.
  });
  retval->sock->Receive(buffy,512*8,*cb);
  return retval;
}


/*
 * 

std::shared_ptr< GlobalGrid::ProtocolDriver > IPProto::CreateDriver(void* connectionManager)
{
  std::shared_ptr<IPDriver> retval = std::make_shared<IPDriver>();
  unsigned char buffy[1024*4];
  retval->sock->Receive(buffy,1024*4,System::Net::F2UDPCB([=](const System::Net::UDPCallback& results){
    std::shared_ptr<IPSocket> s = retval->socketMappings[results.receivedFrom].lock();
    if(!s) {
      s = std::make_shared<IPSocket>(retval->sock);
      s->ep = results.receivedFrom;
      retval->socketMappings[results.receivedFrom] = s;
    }
    GlobalGrid::GlobalGrid_NtfyPacket(connectionManager,s,(unsigned char*)buffy,results.outlen);
  }));
  return retval;
}
 * 
 * */