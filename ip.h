#ifndef GG_IP
#define GG_IP
#include "GlobalGrid.h"
#include "cppext/cppext.h"
namespace IPProto {

class IIPDriver:public GlobalGrid::ProtocolDriver {
public:
  virtual ~IIPDriver(){};
  //Associates an IP address with a given endpoint.
  virtual void AddEndpoint(const System::Net::IPEndpoint& ep, void* key) = 0;
};
std::shared_ptr<IPProto::IIPDriver> CreateDriver(void* connmgr); 



}

#endif