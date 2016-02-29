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


void RSA_Export(void* key, bool includePrivate, unsigned char** output, size_t* len);

void secure_random_bytes(void* output, size_t outlen);


/**
 * @summary Frees an RSA key
 * */
void RSA_Free(void* key);
/**
 * @summary Frees a buffer allocated with RSA_Export
 * */
void RSA_Free_Buffer(void* buffer);


void* RSA_Encrypt(void* key,unsigned char* buffer, size_t bufflen);

void* RSA_Decrypt(void* key, unsigned char* buffer, size_t bufflen);


static inline void RSA_thumbprint(void* key, char* output) {
  unsigned char* tmpbuf;
  size_t len;
  RSA_Export(key,false,&tmpbuf,&len);
  hash_generate(tmpbuf,len,output);
  RSA_Free_Buffer(tmpbuf);
}


static inline void RSA_thumbprint(void* key, unsigned char* output) {
  unsigned char* tmpbuf;
  size_t len;
  RSA_Export(key,false,&tmpbuf,&len);
  hash_generate(tmpbuf,len,output);
  RSA_Free_Buffer(tmpbuf);
}


#endif