#ifndef FREESPEECH_DATABASE
#define FREESPEECH_DATABASE

#include <memory>
#include <string.h>
#include "cppext/cppext.h"

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
  outsz = strlen(obj.id)+1+strlen(obj.name)+1+strlen(obj.parent)+1+strlen(obj.owner)+1+obj.bloblen;
  unsigned char* bytes = (unsigned char*)malloc(outsz);
  System::BStream bstr(bytes,outsz);
  bstr.Write(obj.id);
  bstr.Write(obj.name);
  bstr.Write(obj.parent);
  bstr.Write(obj.owner);
  memcpy(bstr.ptr,obj.blob,obj.bloblen);
  return bytes;
}
/**
 * @summary Deserializes a NamedObject from a byte array of size len.
 * */
static inline void NamedObject_Deserialize(const void* bytes, size_t len, NamedObject& obj) {
  System::BStream str((unsigned char*)bytes,len);
  
  obj.id = str.ReadString();
  obj.name = str.ReadString();
  obj.parent = str.ReadString();
  obj.owner = str.ReadString();
  obj.bloblen = str.length;
  obj.blob = str.Increment(obj.bloblen);
  
}


void DB_FindAuthority(const char* auth,void* thisptr, void(*callback)(void*,unsigned char*,size_t));

void DB_ObjectLookup(const char* id,void* thisptr, void(*callback)(void*,const NamedObject&));
void DB_FindByName(const char* name, const char* parentID, void* thisptr, void(*callback)(void*,const NamedObject&));
/**
 * @summary Attempts to insert a raw NamedObject into the database. Assumes that object has already been sanity-checked.
 * */
void DB_Insert(const NamedObject& obj);

void DB_Insert_Certificate(const char* thumbprint,const unsigned char* cert, size_t bytes, bool isPrivate);

void DB_EnumPrivateKeys(void* thisptr,bool(*callback)(void*,unsigned char*, size_t));

#endif