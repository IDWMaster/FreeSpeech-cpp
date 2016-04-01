#ifndef GG_IP
#define GG_IP
#include "GlobalGrid.h"
#include "cppext/cppext.h"
namespace IPProto {

class IIPDriver:public GlobalGrid::ProtocolDriver {
public:
  virtual ~IIPDriver(){};
  virtual std::shared_ptr<GlobalGrid::VSocket> MakeSocket(const System::Net::IPEndpoint& ep) = 0;
};
std::shared_ptr<IPProto::IIPDriver> CreateDriver(void* connmgr); 



}

#endif