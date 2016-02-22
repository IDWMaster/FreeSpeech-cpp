#ifndef GG_VS
#define GG_VS
#include <stddef.h>


namespace GlobalGrid {

  
class VSocket {
public:
  virtual void Send(const void* data, size_t sz) = 0;
  /**
   * @summary Serializes this VSocket to a Buffer, which must be freed by calling GGObject_Free
   * */
  virtual void* Serialize();
  virtual ~VSocket(){};
};

void* Buffer_Create(size_t sz);

void Buffer_Get(void* buffer,void** out, size_t* sz);

void GGObject_Free(void* obj);





}
#endif