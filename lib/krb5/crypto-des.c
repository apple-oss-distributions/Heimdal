/*
 * Copyright (c) 1997 - 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "krb5_locl.h"

#ifdef HEIM_KRB5_DES

static void
krb5_DES_random_key(krb5_context context,
		    krb5_keyblock *key)
{
    do {
	krb5_generate_random_block(key->keyvalue.data, key->keyvalue.length);
	CCDesSetOddParity(key->keyvalue.data, key->keyvalue.length);
    } while(CCDesIsWeakKey(key->keyvalue.data, key->keyvalue.length));
}

#ifndef __APPLE_PRIVATE__
static void
krb5_DES_schedule_old(krb5_context context,
		      struct key_type *kt,
		      struct key_data *key)
{
    DES_set_key_unchecked(key->key->keyvalue.data, key->schedule->data);
}
#endif

static void
krb5_DES_random_to_key(krb5_context context,
		       krb5_keyblock *key,
		       const void *data,
		       size_t size)
{
    memcpy(key->keyvalue.data, data, key->keyvalue.length);
    CCDesSetOddParity(key->keyvalue.data, key->keyvalue.length);
    if(CCDesIsWeakKey(key->keyvalue.data, key->keyvalue.length))
	_krb5_xor((void *)key->keyvalue.data, (const unsigned char*)"\0\0\0\0\0\0\0\xf0");
}

#ifndef __APPLE_PRIVATE__
static struct _krb5_key_type keytype_des_old = {
    ETYPE_DES_CBC_CRC,
    "des-old",
    56,
    8,
    sizeof(DES_key_schedule),
    krb5_DES_random_key,
    krb5_DES_schedule_old,
    _krb5_des_salt,
    krb5_DES_random_to_key,
    NULL,
    NULL
};
#endif

static struct _krb5_key_type keytype_des = {
    ETYPE_DES_CBC_CRC,
    "des",
    56,
    8,
    sizeof(struct _krb5_evp_schedule),
    krb5_DES_random_key,
    _krb5_evp_schedule,
    _krb5_des_salt,
    krb5_DES_random_to_key,
    _krb5_evp_cleanup,
    EVP_des_cbc
};

static krb5_error_code
CRC32_checksum(krb5_context context,
	       struct _krb5_key_data *key,
	       const void *data,
	       size_t len,
	       unsigned usage,
	       Checksum *C)
{
    uint32_t crc;
    unsigned char *r = C->checksum.data;
    _krb5_crc_init_table ();
    crc = _krb5_crc_update (data, len, 0);
    r[0] = crc & 0xff;
    r[1] = (crc >> 8)  & 0xff;
    r[2] = (crc >> 16) & 0xff;
    r[3] = (crc >> 24) & 0xff;
    return 0;
}

static krb5_error_code
RSA_MD4_checksum(krb5_context context,
		 struct _krb5_key_data *key,
		 const void *data,
		 size_t len,
		 unsigned usage,
		 Checksum *C)
{
    if (CCDigest(kCCDigestMD4, data, len, C->checksum.data) != 0)
	krb5_abortx(context, "md4 checksum failed");
    return 0;
}

static krb5_error_code
RSA_MD4_DES_checksum(krb5_context context,
		     struct _krb5_key_data *key,
		     const void *data,
		     size_t len,
		     unsigned usage,
		     Checksum *cksum)
{
    return _krb5_des_checksum(context, kCCDigestMD4, key, data, len, cksum);
}

static krb5_error_code
RSA_MD4_DES_verify(krb5_context context,
		   struct _krb5_key_data *key,
		   const void *data,
		   size_t len,
		   unsigned usage,
		   Checksum *C)
{
    return _krb5_des_verify(context, kCCDigestMD4, key, data, len, C);
}

static krb5_error_code
RSA_MD5_DES_checksum(krb5_context context,
		     struct _krb5_key_data *key,
		     const void *data,
		     size_t len,
		     unsigned usage,
		     Checksum *C)
{
    return _krb5_des_checksum(context, kCCDigestMD5, key, data, len, C);
}

static krb5_error_code
RSA_MD5_DES_verify(krb5_context context,
		   struct _krb5_key_data *key,
		   const void *data,
		   size_t len,
		   unsigned usage,
		   Checksum *C)
{
    return _krb5_des_verify(context, kCCDigestMD5, key, data, len, C);
}

struct _krb5_checksum_type _krb5_checksum_crc32 = {
    CKSUMTYPE_CRC32,
    "crc32",
    1,
    4,
    0,
    CRC32_checksum,
    NULL
};

struct _krb5_checksum_type _krb5_checksum_rsa_md4 = {
    CKSUMTYPE_RSA_MD4,
    "rsa-md4",
    64,
    16,
    F_CPROOF,
    RSA_MD4_checksum,
    NULL
};

struct _krb5_checksum_type _krb5_checksum_rsa_md4_des = {
    CKSUMTYPE_RSA_MD4_DES,
    "rsa-md4-des",
    64,
    24,
    F_KEYED | F_CPROOF | F_VARIANT,
    RSA_MD4_DES_checksum,
    RSA_MD4_DES_verify
};

struct _krb5_checksum_type _krb5_checksum_rsa_md5_des = {
    CKSUMTYPE_RSA_MD5_DES,
    "rsa-md5-des",
    64,
    24,
    F_KEYED | F_CPROOF | F_VARIANT,
    RSA_MD5_DES_checksum,
    RSA_MD5_DES_verify
};

static krb5_error_code
evp_des_encrypt_null_ivec(krb5_context context,
			  struct _krb5_key_data *key,
			  void *data,
			  size_t len,
			  krb5_boolean encryptp,
			  int usage,
			  void *ignore_ivec)
{
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_CIPHER_CTX *c;
    DES_cblock ivec;
    memset(&ivec, 0, sizeof(ivec));
    c = encryptp ? &ctx->ectx : &ctx->dctx;
    EVP_CipherInit_ex(c, NULL, NULL, NULL, (void *)&ivec, -1);
    EVP_Cipher(c, data, data, len);
    return 0;
}

static krb5_error_code
evp_des_encrypt_key_ivec(krb5_context context,
			 struct _krb5_key_data *key,
			 void *data,
			 size_t len,
			 krb5_boolean encryptp,
			 int usage,
			 void *ignore_ivec)
{
    struct _krb5_evp_schedule *ctx = key->schedule->data;
    EVP_CIPHER_CTX *c;
    DES_cblock ivec;
    memcpy(&ivec, key->key->keyvalue.data, sizeof(ivec));
    c = encryptp ? &ctx->ectx : &ctx->dctx;
    EVP_CipherInit_ex(c, NULL, NULL, NULL, (void *)&ivec, -1);
    EVP_Cipher(c, data, data, len);
    return 0;
}

struct _krb5_encryption_type _krb5_enctype_des_cbc_crc = {
    ETYPE_DES_CBC_CRC,
    "des-cbc-crc",
    8,
    8,
    8,
    &keytype_des,
    &_krb5_checksum_crc32,
    NULL,
    F_DISABLED|F_WEAK|F_WARNING,
    evp_des_encrypt_key_ivec,
    0,
    NULL
};

struct _krb5_encryption_type _krb5_enctype_des_cbc_md4 = {
    ETYPE_DES_CBC_MD4,
    "des-cbc-md4",
    8,
    8,
    8,
    &keytype_des,
    &_krb5_checksum_rsa_md4,
    &_krb5_checksum_rsa_md4_des,
    F_DISABLED|F_WEAK,
    evp_des_encrypt_null_ivec,
    0,
    NULL
};

struct _krb5_encryption_type _krb5_enctype_des_cbc_md5 = {
    ETYPE_DES_CBC_MD5,
    "des-cbc-md5",
    8,
    8,
    8,
    &keytype_des,
    &_krb5_checksum_rsa_md5,
    &_krb5_checksum_rsa_md5_des,
    F_DISABLED|F_WEAK|F_WARNING,
    evp_des_encrypt_null_ivec,
    0,
    NULL
};

struct _krb5_encryption_type _krb5_enctype_des_cbc_none = {
    ETYPE_DES_CBC_NONE,
    "des-cbc-none",
    8,
    8,
    0,
    &keytype_des,
    &_krb5_checksum_none,
    NULL,
    F_PSEUDO|F_DISABLED|F_WEAK|F_WARNING,
    evp_des_encrypt_null_ivec,
    0,
    NULL
};

#ifndef __APPLE_PRIVATE__
static krb5_error_code
DES_CFB64_encrypt_null_ivec(krb5_context context,
			    struct key_data *key,
			    void *data,
			    size_t len,
			    krb5_boolean encryptp,
			    int usage,
			    void *ignore_ivec)
{
    DES_cblock ivec;
    int num = 0;
    DES_key_schedule *s = key->schedule->data;
    memset(&ivec, 0, sizeof(ivec));
	
    DES_cfb64_encrypt(data, data, len, s, &ivec, &num, encryptp);
    return 0;
}

struct _krb5_encryption_type _krb5_enctype_des_cfb64_none = {
    ETYPE_DES_CFB64_NONE,
    "des-cfb64-none",
    1,
    1,
    0,
    &keytype_des_old,
    &_krb5_checksum_none,
    NULL,
    F_PSEUDO|F_DISABLED|F_WEAK|F_WARNING,
    DES_CFB64_encrypt_null_ivec,
    0,
    NULL
};

static krb5_error_code
DES_PCBC_encrypt_key_ivec(krb5_context context,
			  struct key_data *key,
			  void *data,
			  size_t len,
			  krb5_boolean encryptp,
			  int usage,
			  void *ignore_ivec)
{
    DES_cblock ivec;
    DES_key_schedule *s = key->schedule->data;
    memcpy(&ivec, key->key->keyvalue.data, sizeof(ivec));
	
    DES_pcbc_encrypt(data, data, len, s, &ivec, encryptp);
    return 0;
}

struct _krb5_encryption_type _krb5_enctype_des_pcbc_none = {
    ETYPE_DES_PCBC_NONE,
    "des-pcbc-none",
    8,
    8,
    0,
    &keytype_des_old,
    &_krb5_checksum_none,
    NULL,
    F_PSEUDO|F_DISABLED|F_WEAK|F_WARNING,
    DES_PCBC_encrypt_key_ivec,
    0,
    NULL
};

#endif /* __APPLE_PRIVATE__ */

#endif /* HEIM_KRB5_DES */
