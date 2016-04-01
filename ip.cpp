#include "ip.h"
#include "crypto.h"
#include "cppext/cppext.h"
#include <map>


class IPSocket:public GlobalGrid::VSocket {
public:
  System::Net::IPEndpoint ep;
  std::shared_ptr<System::Net::UDPSocket> sock;
  IPSocket(const std::shared_ptr<System::Net::UDPSocket>& sock) {
    this->sock = sock;
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
  void Send(const void* data, size_t sz) {
    sock->Send(data,sz,ep);
  }
};

class IPDriver:public IPProto::IIPDriver {
public:
  std::shared_ptr<System::Net::UDPSocket> sock;
  std::map<System::Net::IPEndpoint,std::weak_ptr<IPSocket>> socketMappings;
  IPDriver() {
    FromHexString("452566E212031284966AB354F7F6CA04",(unsigned char*)id.value,2*16);
    sock = System::Net::CreateUDPSocket(); //Put a sock in itself.
  }
  
  std::shared_ptr< GlobalGrid::VSocket > Deserialize(unsigned char* buffer, size_t bufflen) {
    if(bufflen>=16+2) {
      std::shared_ptr<IPSocket> retval = std::make_shared<IPSocket>(sock);
      memcpy(retval->ep.ip.raw,buffer,16);
      memcpy(&(retval->ep.port),buffer+16,2);
      return retval;
    }else {
      return 0;
    }
  }
std::shared_ptr< GlobalGrid::VSocket > MakeSocket(const System::Net::IPEndpoint& ep) {
  std::shared_ptr<IPSocket> retval = std::make_shared<IPSocket>(sock);
  retval->ep = ep;
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
 
};



std::shared_ptr< IPProto::IIPDriver > IPProto::CreateDriver(void* connectionManager)
{ std::shared_ptr<IPDriver> retval = std::make_shared<IPDriver>();
  unsigned char buffy[1024*4];
  retval->sock->Receive(buffy,1024*4,System::Net::F2UDPCB([=](const System::Net::UDPCallback& results){
    printf("Got IP?\n");
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