#ifndef FREESPEECH_DATABASE
#define FREESPEECH_DATABASE

#include <memory>

class IDisposable {
public:
  virtual ~IDisposable(){};
};


class NamedObject {
public:
  char* id; //Blob ID == hash of contents
  char* name; //Blob name == Friendly name
  char* parent; //Parent Blob ID
  char* owner; //Owner of BLOB
  unsigned char* blob; //Raw BLOB as transmitted over network
  //Blob length
  size_t bloblen;
  
};

/**
 * @summary Serializes a NamedObject to a byte array. The resultant array can be freed with free();
 * */
static inline void* NamedObject_Serialize(const NamedObject& obj, size_t& outsz) {
  
}


void DB_ObjectLookup(const char* id,void* thisptr, void(*callback)(void*,const NamedObject&));
void DB_FindByName(const char* name, const char* parentID, void* thisptr, void(*callback)(void*,const NamedObject&));


#endif