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

#ifndef FS_CRYPTO
#define FS_CRYPTO
#include <stdint.h>
#include <string.h>
#include "GlobalGrid.h"

void aes_encrypt(const void* key, void* data);
void aes_decrypt(const void* key, void* data);


void* RSA_GenKey(size_t bits);

/**
 * @summary Creates an RSA key. Returns the key if successful; otherwise 0. The returned key must be freed by calling RSA_Free.
 * */
void* RSA_Key(unsigned char* data, size_t len);

/**
 * Generates a 16-byte truncated hash in hex-encoded format
 * @param data The data to hash
 * @param len The length of the data to hash
 * @param output A buffer that is at least 33 bytes long.
 * */
void hash_generate(const unsigned char* data, size_t len, char* output);

/**
 * Generates a raw 16-byte truncated hash.
 * */
void hash_generate(const unsigned char* data, size_t len, unsigned char* output);


void* RSA_Export(void* key, bool includePrivate);

void secure_random_bytes(void* output, size_t outlen);


/**
 * @summary Frees an RSA key
 * */
void RSA_Free(void* key);


void* RSA_Encrypt(void* key,unsigned char* buffer, size_t bufflen);

void* RSA_Decrypt(void* key, unsigned char* buffer, size_t bufflen);

static inline void ToHexString(unsigned char* data, size_t sz, char* output) {
  
  const char* hex = "0123456789ABCDEF";
  size_t c = 0;
  for(size_t i = 0;i<sz;i++) {
    output[c] = hex[data[i] >> 4]; //Get lower 4 bits
    c++; //This is how C++ was invented.
    output[c] = hex[((data[i] << 4) & 0xff) >> 4];//Get upper 4 bits
    c++; //This is how C++ was invented.
  }
  output[sz*2] = 0;
}

static inline void FromHexString(const char* hex, unsigned char* output, size_t sz) {
  size_t c = 0;
  
  for(size_t i = 0;i<sz;i+=2) {
    unsigned char word = 0;
    char mander = hex[i];
    if(mander>='A') {
      word = ((mander-'A')+0xA) << 4;
    }else {
      word = (mander-'0') << 4;
    }
    mander = hex[i+1];
    if(mander>='A') {
      word |= ((mander-'A')+0xA);
    }else {
      word |= (mander-'0');
    }
    output[c] = word;
    c++; //This is how C++ was invented
  }
}

static inline void RSA_thumbprint(void* key, char* output) {
  unsigned char* tmpbuf;
  size_t len;
  void* buffer = RSA_Export(key,false);
  GlobalGrid::Buffer_Get(buffer,(void**)&tmpbuf,&len);
  hash_generate(tmpbuf,len,output);
  GlobalGrid::GGObject_Free(buffer);
}


static inline void RSA_thumbprint(void* key, unsigned char* output) {
  unsigned char* tmpbuf;
  size_t len;
  void* buffer = RSA_Export(key,false);
  GlobalGrid::Buffer_Get(buffer,(void**)&tmpbuf,&len);
  hash_generate(tmpbuf,len,output);
  GlobalGrid::GGObject_Free(buffer);
  
}


#endif