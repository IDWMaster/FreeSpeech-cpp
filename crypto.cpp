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

#include "crypto.h"
#include <Windows.h>
#include <assert.h>
#include "cppext\cppext.h"
class Win32CryptoServiceProvider {
public:
	HCRYPTPROV provider_rsa;
	Win32CryptoServiceProvider() {
		CryptAcquireContextW(&provider_rsa, 0, MS_STRONG_PROV, PROV_RSA_FULL, 0);
	}
	~Win32CryptoServiceProvider() {
		CryptReleaseContext(provider_rsa, 0);
	}
};

static Win32CryptoServiceProvider msp;
void secure_random_bytes(void* output, size_t outlen)
{
	CryptGenRandom(msp.provider_rsa, outlen, (BYTE*)output);
}


void aes_encrypt(const void* key, void* data)
{
	struct {
		BLOBHEADER header;
		DWORD keyLen;
		unsigned char key[32];
	} WinKey;
	WinKey.header.bType = PLAINTEXTKEYBLOB;
	WinKey.header.bVersion = CUR_BLOB_VERSION;
	WinKey.header.reserved = 0;
	WinKey.header.aiKeyAlg = CALG_AES_256;
	WinKey.keyLen = 32;
	memcpy(WinKey.key, key, 32);

	HCRYPTKEY winkey = 0;
	CryptImportKey(msp.provider_rsa, (BYTE*)&WinKey, sizeof(WinKey), 0, 0, &winkey);
	assert(winkey != 0);
	DWORD dlen = 0;		
	assert(CryptEncrypt(winkey, 0, 0, 0, (BYTE*)data,&dlen,16));

	
  
}

class BIGNUM {
public:
	const void* ptr;
	size_t len;
	BIGNUM(const void* ptr, size_t len) {
		this->ptr = ptr;
		this->len = len;
	}
};

static BIGNUM ReadBig(System::BStream& str) {
  uint16_t len;
  str.Read(len);
  return BIGNUM(str.Increment(len),len);
}
static void WriteBig(System::BStream& str, const BIGNUM& number) {
  uint16_t len = (uint16_t)number.len;
  str.Write(len);
  memcpy(str.ptr, number.ptr, number.len);
  str.Increment(len);
}

class RSAEncryptionKey {
public:
	unsigned char* blob;
	size_t privateOffset;
	HCRYPTKEY keyHandle;
	size_t len;
	RSAEncryptionKey(unsigned char* blob,size_t blobLen, HCRYPTKEY handle, size_t privateOffset = 0) {
		this->blob = new unsigned char[blobLen];
		memcpy(this->blob,blob,blobLen);
		this->keyHandle = handle;
		this->privateOffset = privateOffset;
		this->len = blobLen;
	}
	~RSAEncryptionKey() {
		CryptDestroyKey(keyHandle);
		delete[] blob;
	}
};

void* RSA_Key(unsigned char* data, size_t len)
{

	struct {
		PUBLICKEYSTRUC pubkeyheader;
		RSAPUBKEY pubkey;
	} MSRSAKEY;

	System::BStream str(data, len);
	size_t startAddr = (size_t)str.ptr;
	try {
		BIGNUM n = ReadBig(str); //Public modulus
		BIGNUM e = ReadBig(str); //Public exponent
		MSRSAKEY.pubkey.bitlen = n.len * 8;
		MSRSAKEY.pubkey.magic = 0x31415352;

		memcpy(&MSRSAKEY.pubkey.pubexp, e.ptr, sizeof(MSRSAKEY.pubkey.pubexp));

		MSRSAKEY.pubkeyheader.bType = PUBLICKEYBLOB;
		MSRSAKEY.pubkeyheader.bVersion = CUR_BLOB_VERSION;
		MSRSAKEY.pubkeyheader.reserved = 0;
		MSRSAKEY.pubkeyheader.aiKeyAlg = CALG_RSA_KEYX;
		size_t endAddr = (size_t)str.ptr;
		if (str.length) {
			//We have private key
			MSRSAKEY.pubkeyheader.bType = PRIVATEKEYBLOB;

			BIGNUM d = ReadBig(str); //Private exponent (privateExponent)
			BIGNUM p = ReadBig(str); //Secret prime factor (prime1)
			BIGNUM q = ReadBig(str); //Secret prime factor (prime2)
			BIGNUM dmp1 = ReadBig(str); //d mod (p-1) (exponent1)
			BIGNUM dmq1 = ReadBig(str); //d mod (q-1) (exponent2)
			BIGNUM iqmp = ReadBig(str); //q^-1 mod p (coefficient)
			//TODO: Return private key
			size_t blob_len = sizeof(MSRSAKEY) + n.len+p.len+q.len+dmp1.len+dmq1.len+iqmp.len;

			unsigned char* privkey_blob = new unsigned char[blob_len];
			unsigned char* ptr = privkey_blob;
			memcpy(privkey_blob, &MSRSAKEY, sizeof(MSRSAKEY));
			ptr += sizeof(MSRSAKEY);
			memcpy(ptr, n.ptr, n.len);
			ptr += n.len;
			memcpy(ptr, p.ptr, p.len);
			ptr += p.len;
			memcpy(ptr, q.ptr, q.len);
			ptr += q.len;
			memcpy(ptr, dmp1.ptr, dmp1.len);
			ptr += dmp1.len;
			memcpy(ptr, dmq1.ptr, dmq1.len);
			ptr += dmq1.len;
			memcpy(ptr, iqmp.ptr, iqmp.len);
			ptr += iqmp.len;
			HCRYPTKEY osHandle = 0;
			CryptImportKey(msp.provider_rsa, privkey_blob, blob_len, 0, 0, &osHandle);
			delete[] privkey_blob;
			if (osHandle == 0) {
				return 0;
			}
			return new RSAEncryptionKey(privkey_blob, blob_len, osHandle,endAddr-startAddr);
		}
		else {
			//TODO: Return public key
			size_t blob_len = sizeof(MSRSAKEY) + n.len;
		    unsigned char* pubkey_blob = new unsigned char[blob_len];
			unsigned char* ptr = pubkey_blob;
			memcpy(pubkey_blob, &MSRSAKEY, sizeof(MSRSAKEY));
			ptr += sizeof(MSRSAKEY);
			memcpy(ptr, n.ptr, n.len);
			HCRYPTKEY osHandle = 0;
			CryptImportKey(msp.provider_rsa, pubkey_blob, blob_len, 0, 0, &osHandle);
			delete[] pubkey_blob;
			if (osHandle == 0) {
				return 0;
			}
			return new RSAEncryptionKey(pubkey_blob, blob_len, osHandle);
			
		}
	}
	catch (const char* err) {
		return 0;
	}
}

void* RSA_Export(void* _key, bool includePrivate)
{
	RSAEncryptionKey* key = (RSAEncryptionKey*)_key;

	if (includePrivate && key->privateOffset) {
		void* retval = GlobalGrid::Buffer_Create(key->len);
		unsigned char* data;
		size_t len;
		GlobalGrid::Buffer_Get(retval, &data, &len);
		memcpy(data, key->blob, len);
		return retval;
	}
	else {
		void* retval = GlobalGrid::Buffer_Create(key->len - key->privateOffset);
		unsigned char* data;
		size_t len;
		GlobalGrid::Buffer_Get(retval, &data, &len);
		memcpy(data, key->blob, len);
		return retval;
	}
}

static void SHA512(const unsigned char* data, size_t len, unsigned char* output) {
	HCRYPTHASH hash = 0;
	CryptCreateHash(msp.provider_rsa, CALG_SHA_512, 0, 0, &hash);
	CryptHashData(hash, data, len, 0);
	DWORD hashlen;
	CryptGetHashParam(hash, HP_HASHVAL, output, &hashlen, 0);
	CryptDestroyHash(hash);

}
void hash_generate(const unsigned char* data, size_t len, char* output)
{
  //Poor unsigned Charmander....
  unsigned char mander[64];
  SHA512(data,len,mander);
  const char* hex = "0123456789ABCDEF";
  size_t c = 0;
  for(size_t i = 0;i<16;i++) {
    output[c] = hex[mander[i] >> 4]; //Get lower 4 bits
    c++; //This is how C++ was invented.
    output[c] = hex[((mander[i] << 4) & 0xff) >> 4];//Get upper 4 bits
    c++; //This is how C++ was invented.
  }
  
}

void hash_generate(const unsigned char* data, size_t len, unsigned char* output)
{

  //Poor unsigned Charmander....
  unsigned char mander[64];
  SHA512(data,len,mander);
  memcpy(output,mander,16);
}



void* RSA_GenKey(size_t bits)
{
 // BIGNUM* e = BN_new();
  //  BN_set_word(e, 65537);
	uint32_t keySize = (uint32_t)bits;
	HCRYPTKEY key = 0;
	CryptGenKey(msp.provider_rsa, CALG_RSA_KEYX, CRYPT_EXPORTABLE | (bits >> (32 - 16)),&key);
	assert(key != 0);
	DWORD dlen = 0;
	CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, 0, &dlen);
	unsigned char* mander = new unsigned char[dlen];
	CryptExportKey(key, 0, PRIVATEKEYBLOB, 0, mander, &dlen);
	struct {
		PUBLICKEYSTRUC pubkeyheader;
		RSAPUBKEY pubkey;
	} MSRSAKEY;
	unsigned char* ptr = mander;
	memcpy(&MSRSAKEY, ptr, sizeof(MSRSAKEY));
	ptr += sizeof(MSRSAKEY);

	delete[] mander;
  RSA* msa = RSA_generate_key(bits,65537,0,0);
  //BN_free(e);
  return msa;
}




void RSA_Free(void* key)
{
  RSA_free((RSA*)key);
}

void* RSA_Encrypt(void* _key, unsigned char* input, size_t inlen)
{
  RSA* key = (RSA*)_key;
  void* outbuf = GlobalGrid::Buffer_Create(RSA_size(key));
  unsigned char* output;
  size_t outlen;
  GlobalGrid::Buffer_Get(outbuf,(void**)&output,&outlen);
  RSA_public_encrypt(inlen,input,output,key,RSA_PKCS1_PADDING);
  return outbuf;
}

void* RSA_Decrypt(void* _key, unsigned char* input, size_t inlen)
{
  RSA* key = (RSA*)_key;
  size_t outlen = RSA_size(key);
  unsigned char* output = (unsigned char*)malloc(outlen);
  int sz = RSA_private_decrypt(inlen,input,output,key,RSA_PKCS1_PADDING);
  if(sz<=0) {
    free(output);
    return 0;
  }
  void* outbuf = GlobalGrid::Buffer_Create(sz);
  void* a;
  size_t b;
  GlobalGrid::Buffer_Get(outbuf,&a,&b);
  memcpy(a,output,sz);
  free(output);
  return outbuf;
}






void aes_decrypt(const void* key, void* data)
{
	struct {
		BLOBHEADER header;
		DWORD keyLen;
		unsigned char key[32];
	} WinKey;
	WinKey.header.bType = PLAINTEXTKEYBLOB;
	WinKey.header.bVersion = CUR_BLOB_VERSION;
	WinKey.header.reserved = 0;
	WinKey.header.aiKeyAlg = CALG_AES_256;
	WinKey.keyLen = 32;
	memcpy(WinKey.key, key, 32);

	HCRYPTKEY winkey = 0;
	CryptImportKey(msp.provider_rsa, (BYTE*)&WinKey, sizeof(WinKey), 0, 0, &winkey);
	assert(winkey != 0);
	DWORD dlen = 0;
	assert(CryptDecrypt(winkey, 0, 0, 0, (BYTE*)data, &dlen, 16));

}
