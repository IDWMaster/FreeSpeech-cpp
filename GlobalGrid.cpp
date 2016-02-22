#include "GlobalGrid.h"
#include <stdlib.h>

class IDisposable {
public:
  ~IDisposable(){};
};

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
