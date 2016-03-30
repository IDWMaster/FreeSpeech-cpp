#ifndef GG_IP
#define GG_IP
#include "GlobalGrid.h"
namespace IPProto {


std::shared_ptr<GlobalGrid::ProtocolDriver> CreateDriver(void* connmgr); 

}

#endif