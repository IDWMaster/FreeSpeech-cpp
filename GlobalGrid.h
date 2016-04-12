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

#ifndef GG_VS
#define GG_VS
#include <stddef.h>
#include <memory>
#include <string.h>
namespace GlobalGrid {



class VSocket {
public:
  virtual void Send(const void* data, size_t sz) = 0;
  /**
   * @summary Serializes this VSocket to a Buffer, which must be freed by calling GGObject_Free
   * */
  virtual void* Serialize() = 0;
  virtual ~VSocket(){};
};

class Guid {
public:
  uint64_t value[2];
  Guid() {
    
  }
  Guid(uint64_t* val) {
    value[0] = val[0];
    value[1] = val[1];
  }
  bool operator<(const Guid& other) const {
    return memcmp(value,other.value,16) < 0;
  }
};

class ProtocolDriver {
public:
  //Protocol driver ID
  Guid id;
  virtual std::shared_ptr<VSocket> Deserialize(unsigned char* buffer, size_t bufflen) = 0;
  virtual void* SerializeLocalSocket() = 0; //Serializes a socket containing localized connection information. Can be used for diagnostics purposes.
  virtual ~ProtocolDriver(){};
};


void* Buffer_Create(size_t sz);
void Buffer_Get(void* buffer,void** out, size_t* sz);

template<typename T>
static inline void Buffer_Get(void* buffer, T** out, size_t* sz) {
  Buffer_Get(buffer,(void**)out,sz);
}

void GGObject_Free(void* obj);

void GlobalGrid_NtfyPacket(void* connectionManager, std::shared_ptr<VSocket>, unsigned char* packet, size_t packetlength);
void* GlobalGrid_InitRouter(void* encryptionKey);
void GlobalGrid_RegisterProtocolDriver(void* connectionManager,std::shared_ptr<ProtocolDriver> driver);
void GlobalGrid_InitiateHandshake(void* connectionManager, std::shared_ptr<VSocket> socket, void* remoteKey);

}
#endif