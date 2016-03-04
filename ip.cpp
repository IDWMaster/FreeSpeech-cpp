#include "ip.h"
#include "crypto.h"


class IPDriver:public GlobalGrid::ProtocolDriver {
public:
  IPDriver() {
    FromHexString("452566E212031284966AB354F7F6CA04",(unsigned char*)id.value,2*16);
  }
  std::shared_ptr< GlobalGrid::VSocket > Deserialize(unsigned char* buffer, size_t bufflen) {
    return 0;
  }
};





