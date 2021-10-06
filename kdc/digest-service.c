/*
 * Copyright (c) 2006 - 2007 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2011 Apple Inc. All rights reserved.
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

#define HC_DEPRECATED_CRYPTO

#include "headers.h"

typedef struct pk_client_params pk_client_params;
struct DigestREQ;
struct Kx509Request;
#include <kdc-private.h>

#include <asn1-common.h>
#include <digest_asn1.h>
#include <heimntlm.h>
#include <roken.h>

#include <gssapi.h>
#include <gssapi_spi.h>
#include <gssapi_ntlm.h>

#include "heimbase.h"

#ifdef HAVE_OPENDIRECTORY

#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>
#include <SystemConfiguration/SCPreferences.h>

#endif

#if defined(__APPLE_PRIVATE__) && !defined(__APPLE_TARGET_EMBEDDED__)
#include <dlfcn.h>
#define HAVE_APPLE_NETLOGON 1
#endif

static krb5_kdc_configuration *config = NULL;

static const char *
derive_version_ntq(const NTLMRequest2 *ntq)
{
    if ((ntq->ntlmFlags & NTLM_NEG_NTLM2_SESSION) &&
	(ntq->lmChallengeResponse.length >= 8) &&
	(ntq->ntChallengeResponse.length == 24))
	return "ntlmv1-with-v2-session";
    if (ntq->ntChallengeResponse.length == 24)
	return "ntlmv1";
    if (ntq->ntChallengeResponse.length > 24)
	return "ntlmv2";
    if (ntq->ntChallengeResponse.length == 0)
	return "lm";
    return "unknown";
}

static void
log_complete(krb5_context context,
	     const char *type,
	     const NTLMReply *ntp,
	     krb5_error_code ret,
	     const char *ntlm_version)
{

    if (ntp->success) {
	char str[256] = { 0 } ;
	heim_ntlm_unparse_flags(ntp->ntlmFlags, str, sizeof(str));

	kdc_log(context, config, 1, "digest-request %s: ok user=%s\\%s proto=%s flags: %s",
		type,
		ntp->domain, ntp->user, ntlm_version, str);
    } else
	kdc_log(context, config, 1, "digest-request: %s failed with %d proto=%s", type, ret, ntlm_version);
}


#ifdef ENABLE_NTLM

struct ntlm_ftable {
    void		*ctx;
    krb5_error_code	(*init)(krb5_context, void **);
    void		(*fini)(void *);
    int			(*ti)(void *, struct ntlm_targetinfo *ti);
    uint32_t		(*filter_flags)(void *ctx);
    int			(*authenticate)(void *ctx,
					krb5_context context,
					const NTLMRequest2 *ntq,
					void *response_ctx,
					void (response)(void *, const NTLMReply *reply));
};

static uint32_t
kdc_flags(void *ctx)
{
    return 0;
}


static int
kdc_authenticate(void *ctx,
		 krb5_context context,
		 const NTLMRequest2 *ntq,
		 void *response_ctx,
		 void (response)(void *, const NTLMReply *ntp))
{
    krb5_principal client;
    unsigned char sessionkey[16];
    krb5_data sessionkeydata;
    hdb_entry_ex *user = NULL;
    Key *key = NULL;
    NTLMReply ntp;
    const char *ntlm_version = "unknown";
    int ret;
    
    krb5_data_zero(&sessionkeydata);
    memset(&ntp, 0, sizeof(ntp));
    
    kdc_log(context, config, 1, "digest-request: user=%s\\%s",
	    ntq->loginDomainName, ntq->loginUserName);
    
    if (ntq->lmchallenge.length != 8){
	ret = EINVAL;
	goto failed;
    }
    
    if (ntq->ntChallengeResponse.length == 0) {
	ret = EINVAL;
	goto failed;
    }
    
    ret = krb5_make_principal(context, &client, ntq->loginDomainName,
			      ntq->loginUserName, NULL);
    if (ret)
	goto failed;
    
    krb5_principal_set_type(context, client, KRB5_NT_NTLM);
    
    ret = _kdc_db_fetch(context, config, client,
			HDB_F_GET_CLIENT, NULL, &user);
    krb5_free_principal(context, client);
    if (ret)
	goto failed;
    
    if (user->entry.principal->name.name_string.len < 1) {
	kdc_log(context, config, 2,
		"digest-request: user %s\\%s, have weired name",
		ntq->loginDomainName, ntq->loginUserName);
	goto failed;
    }
    
    ntp.domain = user->entry.principal->realm;
    ntp.user = user->entry.principal->name.name_string.val[0];
    
    ret = hdb_enctype2key(context, &user->entry,
			  ETYPE_ARCFOUR_HMAC_MD5, &key);
    if (ret) {
	kdc_log(context, config, 2,
		"digest-request: user %s\\%s, missing NTLM key",
		ntp.domain, ntp.user);
	goto failed;
    }
    
    kdc_log(context, config, 2,
	    "digest-request: found user, processing ntlm request", ret);
    
    if (ntq->ntChallengeResponse.length != 24) {
	struct ntlm_buf targetinfo, answer;
	unsigned char ntlmv2[16];
	
	ntlm_version = "ntlmv2";
	
	if (!gss_mo_get(GSS_NTLM_MECHANISM, GSS_C_NTLM_V2, NULL)) {
	    kdc_log(context, config, 2, "NTLMv2 disabled");
	    goto failed;
	}
	
#if 0 /* if there is an LM2 challange we should check it */
	if (ntq->lmChallengeResponse.length < 8) {
	    kdc_log(context, config, 2,
		    "lmChallengeResponse field is < 8 (%d)",
		    (int)ntq->lmChallengeResponse.length);
	    goto failed;
	}
#endif
	
	answer.length = ntq->ntChallengeResponse.length;
	answer.data = ntq->ntChallengeResponse.data;
	
	ret = heim_ntlm_verify_ntlm2(key->key.keyvalue.data,
				     key->key.keyvalue.length,
				     ntq->loginUserName,
				     ntq->loginDomainName,
				     0,
				     ntq->lmchallenge.data,
				     &answer,
				     &targetinfo,
				     ntlmv2);
	if (ret) {
	    kdc_log(context, config, 2,
		    "digest-request: verify ntlm2 hash failed", ret);
	    goto failed;
	}
	
	/* XXX session key is something like this, let fix it up later */
	if (0 && (ntq->ntlmFlags & NTLM_NEG_NTLM2_SESSION)) {
	    CCHmacContext c;
	    
	    kdc_log(context, config, 2,
		    "digest-request: digest session key");
	    
	    CCHmacInit(&c, kCCHmacAlgMD5, ntlmv2, sizeof(ntlmv2));
	    CCHmacUpdate(&c, ntq->lmchallenge.data, ntq->lmchallenge.length);
	    CCHmacUpdate(&c, ntq->lmChallengeResponse.data,
			 ntq->lmChallengeResponse.length);
	    CCHmacFinal(&c, sessionkey);
	    memset(&c, 0, sizeof(c));
	} else {
	    size_t len = MIN(ntq->ntChallengeResponse.length, 16);
	    CCHmacContext c;
	    
	    kdc_log(context, config, 2,
		    "digest-request: basic key");
	    
	    CCHmacInit(&c, kCCHmacAlgMD5, ntlmv2, sizeof(ntlmv2));
	    CCHmacUpdate(&c, ntq->ntChallengeResponse.data, len);
	    CCHmacFinal(&c, sessionkey);
	    memset(&c, 0, sizeof(c));
	}
	
	memset(ntlmv2, 0, sizeof(ntlmv2));
	
	ntp.targetinfo.data = targetinfo.data;
	ntp.targetinfo.length = targetinfo.length;
	
    } else {
	struct ntlm_buf answer;
	uint8_t challenge[8];
	uint8_t usk[16];
	CCDigestRef ctx;
	
	ntlm_version = "ntlmv1";
	
	if (!gss_mo_get(GSS_NTLM_MECHANISM, GSS_C_NTLM_V1, NULL)) {
	    kdc_log(context, config, 2, "NTLMv1 disabled");
	    goto failed;
	}
	
	if (ntq->lmchallenge.length != 8)
	    goto failed;
	
	if (ntq->ntlmFlags & NTLM_NEG_NTLM2_SESSION) {
	    unsigned char sessionhash[CC_MD5_DIGEST_LENGTH];
	    CCDigestRef md5ctx;
	    
	    /* the first first 8 bytes is the challenge, what is the other 16 bytes ? */
	    if (ntq->lmChallengeResponse.length != 24)
		goto failed;
	    
	    md5ctx = CCDigestCreate(kCCDigestMD5);
	    CCDigestUpdate(md5ctx, ntq->lmchallenge.data, 8);
	    CCDigestUpdate(md5ctx, ntq->lmChallengeResponse.data, 8);
	    CCDigestFinal(md5ctx, sessionhash);
	    CCDigestDestroy(md5ctx);
	    memcpy(challenge, sessionhash, sizeof(challenge));
	} else {
	    memcpy(challenge, ntq->lmchallenge.data, ntq->lmchallenge.length);
	}
	
	ret = heim_ntlm_calculate_ntlm1(key->key.keyvalue.data,
					key->key.keyvalue.length,
					challenge, &answer);
	if (ret)
	    goto failed;
	
	if (ntq->ntChallengeResponse.length != answer.length ||
	    memcmp(ntq->ntChallengeResponse.data, answer.data, answer.length) != 0) {
	    free(answer.data);
	    kdc_log(context, config, 2,
		    "digest-request: verify ntlm1 hash failed", ret);
	    ret = EINVAL;
	    goto failed;
	}
	free(answer.data);
	
	ctx = CCDigestCreate(kCCDigestMD4);
	CCDigestUpdate(ctx,
		       key->key.keyvalue.data,
		       key->key.keyvalue.length);
	CCDigestFinal(ctx, usk);
	CCDigestDestroy(ctx);
	
	
	if ((ntq->ntlmFlags & NTLM_NEG_NTLM2_SESSION) != 0) {
	    CCHmacContext hc;
	    
	    CCHmacInit(&hc, kCCHmacAlgMD5, usk, sizeof(usk));
	    CCHmacUpdate(&hc, ntq->lmchallenge.data, 8);
	    CCHmacUpdate(&hc, ntq->lmChallengeResponse.data, 8);
	    CCHmacFinal(&hc, sessionkey);
	    memset(&hc, 0, sizeof(hc));
	} else {
	    memcpy(sessionkey, usk, sizeof(sessionkey));
	}
    }
    
    if (ntq->ntlmFlags & NTLM_NEG_KEYEX) {
	struct ntlm_buf base, enc, sess;
	
	base.data = sessionkey;
	base.length = sizeof(sessionkey);
	enc.data = ntq->encryptedSessionKey.data;
	enc.length = ntq->encryptedSessionKey.length;
	
	ret = heim_ntlm_keyex_unwrap(&base, &enc, &sess);
	if (ret != 0)
	    goto failed;
	if (sess.length != sizeof(sessionkey)) {
	    heim_ntlm_free_buf(&sess);
	    ret = EINVAL;
	    goto failed;
	}
	memcpy(sessionkey, sess.data, sizeof(sessionkey));
	heim_ntlm_free_buf(&sess);
    }
    
    sessionkeydata.data = sessionkey;
    sessionkeydata.length = sizeof(sessionkey);
    ntp.sessionkey = &sessionkeydata;
    
    ntp.success = 1;
    ntp.ntlmFlags = ntq->ntlmFlags;
    
    (*response)(response_ctx, &ntp);

failed:
    log_complete(context, "kdc", &ntp, ret, ntlm_version);

    if (ntp.targetinfo.data)
	free(ntp.targetinfo.data);
    
    if (user)
	_kdc_free_ent (context, user);
    
    return ret;
}

/*
 *
 */

static uint32_t
guest_flags(void *ctx)
{
    return 0;
}

static int
guest_authenticate(void *ctx,
		   krb5_context context,
		   const NTLMRequest2 *ntq,
		   void *response_ctx,
		   void (response)(void *, const NTLMReply *ntp))
{
    unsigned char sessionkey[16];
    krb5_data sessionkeydata;
    NTLMReply ntp;
    int is_guest = (strcasecmp("GUEST", ntq->loginUserName) == 0);
    int ret = EINVAL;
    
    memset(&ntp, 0, sizeof(ntp));

    if (is_guest || (ntq->ntlmFlags & NTLM_NEG_ANONYMOUS)) {
	kdc_log(context, config, 2,
		"digest-request: found guest, let in");
	ntp.flags |= nTLM_anonymous;
	ntp.user = "GUEST";
	ntp.domain = ntq->loginDomainName;
	if (ntp.user == NULL || ntp.domain == NULL)
	    goto out;
	
	if (is_guest) {
	    /* no password */
	    CCDigest(kCCDigestMD4, (void *)"", 0, sessionkey);
	}
    } else {
	ret = EINVAL;
	goto out;
    }
    
    
    if (ntq->ntlmFlags & NTLM_NEG_KEYEX) {
	struct ntlm_buf base, enc, sess;
	
	base.data = sessionkey;
	base.length = sizeof(sessionkey);
	enc.data = ntq->encryptedSessionKey.data;
	enc.length = ntq->encryptedSessionKey.length;
	
	ret = heim_ntlm_keyex_unwrap(&base, &enc, &sess);
	if (ret != 0)
	    goto out;
	if (sess.length != sizeof(sessionkey)) {
	    heim_ntlm_free_buf(&sess);
	    ret = EINVAL;
	    goto out;
	}
	memcpy(sessionkey, sess.data, sizeof(sessionkey));
	heim_ntlm_free_buf(&sess);
    }

    sessionkeydata.data = sessionkey;
    sessionkeydata.length = sizeof(sessionkey);
    ntp.sessionkey = &sessionkeydata;

    ntp.ntlmFlags = ntq->ntlmFlags;
    ntp.success = 1;
    
    response(response_ctx, &ntp);
    ret = 0;
out:
    log_complete(context, "guest", &ntp, ret, derive_version_ntq(ntq));

    return ret;
}

/*
 *
 */

#ifdef HAVE_OPENDIRECTORY

struct ntlmod {
    ODNodeRef node;
};

/*
 *
 */

static CFArrayRef meta_keys;
static char *ntlmDomain;

static void
update_ntlm(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info)
{
    CFDictionaryRef settings;
    CFStringRef n;
    
    if (store == NULL)
	return;
    
    settings = (CFDictionaryRef)SCDynamicStoreCopyValue(store, CFSTR("com.apple.smb"));
    if (settings == NULL)
	return;
    
    n = CFDictionaryGetValue(settings, CFSTR("NetBIOSName"));
    if (n == NULL || CFGetTypeID(n) != CFStringGetTypeID())
	goto fin;
    
    if (ntlmDomain)
	free(ntlmDomain);
    ntlmDomain = rk_cfstring2cstring(n);
    strupr(ntlmDomain);
    
fin:
    CFRelease(settings);
    return;
}

static void
ntlm_notification(void)
{
    SCDynamicStoreRef store;
    dispatch_queue_t queue;
    
    store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("com.apple.Kerberos.gss-od"), update_ntlm, NULL);
    if (store == NULL)
	return;
    
    CFTypeRef key[] = {CFSTR("com.apple.smb")};
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, key, 1, NULL);
    SCDynamicStoreSetNotificationKeys(store, keys, NULL);
    CFRelease(keys);
    
    queue = dispatch_queue_create("com.apple.gss-od.ntlm-name", NULL);
    if (queue == NULL) {
	CFRelease(store);
	errx(1, "dispatch_queue_create");
    }
    
    SCDynamicStoreSetDispatchQueue(store, queue);
    CFRelease(store);
    
    dispatch_sync(queue, ^{ update_ntlm(store, NULL, NULL); });
}


static void
load_meta_keys(void)
{
    CFMutableArrayRef keys;
    
    keys = CFArrayCreateMutable(NULL, 1, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(keys, kODAttributeTypeMetaNodeLocation);
    meta_keys = keys;
}


static int
od_init(krb5_context config, void **ctx)
{
    static dispatch_once_t once;
    struct ntlmod *c;
    
    dispatch_once(&once, ^{ 
	ntlm_notification();
	load_meta_keys();
    });
    
    if (ntlmDomain == NULL)
	return ENOENT;
    
    c = calloc(1, sizeof(*c));
    if (c == NULL)
	return ENOMEM;
    
    c->node = ODNodeCreateWithNodeType(kCFAllocatorDefault,
				       kODSessionDefault,
				       kODNodeTypeAuthentication, NULL);
    if (c->node == NULL) {
	free(c);
	return ENOENT;
    }
    
    *ctx = c;

    return 0;
}


static uint32_t
od_flags(void *ctx)
{
    CFArrayRef subnodes;
    ODNodeRef node;
    CFIndex num;

    node = ODNodeCreateWithName(kCFAllocatorDefault, kODSessionDefault, CFSTR("/LDAPv3"), NULL);
    if (node == NULL)
	return 0;
    
    subnodes = ODNodeCopySubnodeNames(node, NULL);
    CFRelease(node);
    
    if (subnodes == NULL)
	return 0;
    
    num = CFArrayGetCount(subnodes);
    CFRelease(subnodes);
    if (num == 0)
	return 0;
    
    /*
     * Drat we have OD configured, since it doesn't return signing keys, we must turn that off for everyone!
     */
    
    return NTLM_NEG_SIGN | NTLM_NEG_SEAL |
	NTLM_NEG_ALWAYS_SIGN | NTLM_NEG_NTLM2_SESSION |
	NTLM_NEG_KEYEX;
}

static int
od_authenticate(void *ctx,
		krb5_context context,
		const NTLMRequest2 *ntq,
		void *response_ctx,
		void (response)(void *, const NTLMReply *ntp))
{
    struct ntlmod *c = ctx;
    CFArrayRef outAuthItems = NULL;
    CFMutableArrayRef authItems = NULL;
    ODRecordRef record = NULL;
    Boolean b;
    CFStringRef username = NULL, domain = NULL;
    CFErrorRef error = NULL;
    CFMutableDataRef challenge = NULL, resp = NULL;
    CFArrayRef values = NULL;
    NTLMReply ntp;
    int ret = EINVAL;

    if (ntlmDomain == NULL || ctx == NULL)
	return EINVAL;

    memset(&ntp, 0, sizeof(ntp));
    
    username = CFStringCreateWithCString(NULL, ntq->loginUserName,
					 kCFStringEncodingUTF8);
    if (username == NULL) {
	ret = EINVAL;
	goto out;
    }
    
    challenge = CFDataCreateMutable(NULL, 0);
    if (challenge == NULL) {
	ret = EINVAL;
	goto out;
    }
    CFDataAppendBytes(challenge, ntq->lmchallenge.data, ntq->lmchallenge.length);
    
    resp = CFDataCreateMutable(NULL, 0);
    if (response == NULL) {
	ret = EINVAL;
	goto out;
    }
    CFDataAppendBytes(resp, ntq->ntChallengeResponse.data, ntq->ntChallengeResponse.length);
    
    domain = CFStringCreateWithCString(NULL, ntq->loginDomainName, kCFStringEncodingUTF8);
    if (domain == NULL) {
	ret = EINVAL;
	goto out;
    }
    
    authItems = CFArrayCreateMutable(NULL, 5, &kCFTypeArrayCallBacks);
    if (authItems == NULL) {
	ret = EINVAL;
	goto out;
    }
    
    CFArrayAppendValue(authItems, username);
    CFArrayAppendValue(authItems, challenge);
    CFArrayAppendValue(authItems, resp);
    CFArrayAppendValue(authItems, username);
    CFArrayAppendValue(authItems, domain);
    
    record = ODNodeCopyRecord(c->node, kODRecordTypeUsers, 
			      username, meta_keys, &error);
    if (record == NULL) {
	ret = EINVAL;
	goto out;
    }
    
    values = ODRecordCopyValues(record, kODAttributeTypeMetaNodeLocation, NULL);
    if (values && CFArrayGetCount(values) > 0) {
	CFStringRef str = (CFStringRef)CFArrayGetValueAtIndex(values, 0);
	if (CFStringGetTypeID() != CFGetTypeID(str)) {
	    ret = EINVAL;
	    goto out;
	}
	if (!CFStringHasPrefix(str, CFSTR("/LDAPv3/"))) {
	    ret = ENOENT;
	    goto out;
	}
    }
    
    b = ODRecordVerifyPasswordExtended(record,
				       kODAuthenticationTypeNTLMv2,
				       authItems, &outAuthItems, NULL,
				       &error);
    
    if (!b) {
	ret = ENOENT;
	goto out;
    }
    
    /*
     * No ntlmv2 session key or keyex for OD.
     */
    ntp.ntlmFlags = ntq->ntlmFlags;
    ntp.ntlmFlags &= ~(NTLM_NEG_KEYEX|NTLM_NEG_NTLM2_SESSION);
    
    /*
     * If the NTLMv2 session key is supported, it is returned in the
     * output buffer
     */
    

    if (outAuthItems && CFArrayGetCount(outAuthItems) > 0) {
	CFDataRef data = (CFDataRef)CFArrayGetValueAtIndex(outAuthItems, 0);
	if (CFGetTypeID(data) == CFDataGetTypeID() && CFDataGetLength(data) >= 16) {
	    ntp.sessionkey = calloc(1, sizeof(*ntp.sessionkey));
	    if (ntp.sessionkey == NULL) {
		ret = ENOMEM;
		goto out;
	    }
	    krb5_data_copy(ntp.sessionkey, CFDataGetBytePtr(data), 16);
	}
    }
    
    /*
     * If no session key was passed back, strip of SIGN/SEAL
     */

    if (ntp.sessionkey == NULL || ntp.sessionkey->length == 0)
	ntp.ntlmFlags &= ~(NTLM_NEG_SIGN|NTLM_NEG_SEAL|NTLM_NEG_ALWAYS_SIGN);


    ntp.user = ntq->loginUserName;
    ntp.domain = ntlmDomain;
    
    ntp.success = 1;
    response(response_ctx, &ntp);
    ret = 0;
    
out:
    log_complete(context, "od", &ntp, ret, derive_version_ntq(ntq));
    
    if (values)
	CFRelease(values);
    if (error)
	CFRelease(error);
    if (challenge)
	CFRelease(challenge);
    if (resp)
	CFRelease(resp);
    if (username)
	CFRelease(username);
    if (domain)
	CFRelease(domain);
    if (authItems)
	CFRelease(authItems);
    if (outAuthItems)
	CFRelease(outAuthItems);
    if (record)
	CFRelease(record);
    
    return ret;
}

#endif

#ifdef HAVE_APPLE_NETLOGON

#define LOGON_USER				0x00000001L
#define LOGON_NOENCRYPTION			0x00000002L
#define LOGON_CACHED_ACCOUNT			0x00000004L
#define LOGON_USED_LM_PASSWORD			0x00000008L
#define LOGON_EXTRA_SIDS			0x00000020L
#define LOGON_SUBAUTH_SESSION_KEY		0x00000040L
#define LOGON_SERVER_TRUST_ACCOUNT		0x00000080L
#define LOGON_NTLMV2_ENABLED			0x00000100L
#define LOGON_RESOURCE_GROUPS			0x00000200L
#define LOGON_PROFILE_PATH_RETURNED		0x00000400L
#define LOGON_NT_V2				0x00000800L
#define LOGON_LM_V2				0x00001000L
#define LOGON_NTLM_V2				0x00002000L

#define NTLM_LOGON_REQ_VERSION    1

typedef struct _NTLM_LOGON_REQ {
    uint32_t Version;
    const char *LogonDomainName;
    const char *UserName;
    const char *Workstation;
    uint8_t LmChallenge[8];
    const uint8_t *NtChallengeResponse;
    uint16_t NtChallengeResponseLength;
    const uint8_t *LmChallengeResponse;
    uint16_t LmChallengeResponseLength;
} NTLM_LOGON_REQ, *PNTLM_LOGON_REQ;

typedef uint32_t
(*NTLM_LOGON_FN)(const NTLM_LOGON_REQ *LogonReq,
		 uint8_t **pAuthData,
		 size_t *pAuthDataSize,
		 char **pAccountName,
		 char **pAccountDomain,
		 uint8_t SessionKey[16],
		 uint32_t *Flags);

typedef enum _NETLOGON_PROBE_STATUS {
    NETLOGON_PROBE_UNAVAILABLE = -1,    /* Could not reach RPC server */
    NETLOGON_PROBE_NOT_CONFIGURED = 0,  /* RPC server available but not joined to domain */
    NETLOGON_PROBE_CONFIGURED = 1,      /* RPC server available and joined to domain */
    NETLOGON_PROBE_CONNECTED = 2        /* RPC server available and secure channel up */
} NETLOGON_PROBE_STATUS;

typedef NETLOGON_PROBE_STATUS
(*NET_LOGON_PROBE_FN)(const char *, char **);

/*
 *
 */

struct ntlmnetr {
    OM_uint32 flags;
    char *domain;
};

/*
 *
 */

static char *netlogonDomain;
static char *netlogonServer;


static void
update_domain(SCDynamicStoreRef store, CFArrayRef changedKeys, void *info)
{
    CFDictionaryRef settings;
    CFStringRef n;
    size_t len;

    if (store == NULL)
	return;

    settings = (CFDictionaryRef)SCDynamicStoreCopyValue(store, CFSTR("com.apple.opendirectoryd.ActiveDirectory"));
    if (settings == NULL)
	return;

    n = CFDictionaryGetValue(settings, CFSTR("DomainNameFlat"));
    if (n == NULL || CFGetTypeID(n) != CFStringGetTypeID())
	goto fin;

    if (netlogonDomain)
	free(netlogonDomain);
    netlogonDomain = rk_cfstring2cstring(n);

    n = CFDictionaryGetValue(settings, CFSTR("TrustAccount"));
    if (n == NULL || CFGetTypeID(n) != CFStringGetTypeID())
	goto fin;

    if (netlogonServer)
	free(netlogonServer);
    netlogonServer = rk_cfstring2cstring(n);

    len = strlen(netlogonServer);
    if (len > 1 && netlogonServer[len - 1] == '$')
	netlogonServer[len - 1] = '\0';

    strupr(netlogonServer);

fin:
    CFRelease(settings);
    return;
}


static void
domain_notification(void)
{
    SCDynamicStoreRef store;
    dispatch_queue_t queue;

    store = SCDynamicStoreCreate(kCFAllocatorDefault, CFSTR("com.apple.Kerberos.gss-netlogon"), update_domain, NULL);
    if (store == NULL)
	return;

    CFTypeRef key[] = {CFSTR("com.apple.opendirectoryd.ActiveDirectory")};
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, key, 1, NULL);
    SCDynamicStoreSetNotificationKeys(store, keys, NULL);
    CFRelease(keys);

    queue = dispatch_queue_create("com.apple.gss-netlogon.ntlm-name", NULL);
    if (queue == NULL) {
	CFRelease(store);
	errx(1, "dispatch_queue_create");
    }

    SCDynamicStoreSetDispatchQueue(store, queue);

    dispatch_sync(queue, ^{ update_domain(store, NULL, NULL); });
}


/*
 *
 */

static void *nt_framework_handle = NULL;
static NET_LOGON_PROBE_FN netLogonProbe = NULL;
static NTLM_LOGON_FN nTLMLogon = NULL;

#define NT_FRAMEWORK_PATH "/System/Library/PrivateFrameworks/nt.framework/nt"

static void
init_nt_framework(void *ctx)
{
    nt_framework_handle = dlopen(NT_FRAMEWORK_PATH, RTLD_LOCAL);
    if (nt_framework_handle == NULL)
	return;

    netLogonProbe = dlsym(nt_framework_handle, "NetLogonProbe");
    nTLMLogon = dlsym(nt_framework_handle, "NTLMLogon");


    if (netLogonProbe && nTLMLogon) {
	domain_notification();
    }
}



static int
netr_init(krb5_context config, void **ctx)
{
    static heim_base_once_t init_once = HEIM_BASE_ONCE_INIT;
    NETLOGON_PROBE_STATUS probeStatus;
    struct ntlmnetr *c;
    char *domain;

    heim_base_once_f(&init_once, NULL, init_nt_framework);

    if (netLogonProbe == NULL || nTLMLogon == NULL)
	return ENOENT;

    probeStatus = netLogonProbe(NULL, &domain);
    switch (probeStatus) {
    case NETLOGON_PROBE_CONFIGURED:
    case NETLOGON_PROBE_CONNECTED:
	break;
    default:
	return ENOENT;
    }

    c = calloc(1, sizeof(*c));
    if (c == NULL) {
	free(domain);
	return ENOMEM;
    }
    c->domain = domain;

    *ctx = c;

    return GSS_S_COMPLETE;
}

static uint32_t
netr_flags(void *ctx)
{
    return 0;
}

static int
netr_ti(void *ctx, struct ntlm_targetinfo *ti)
{
    if (netlogonServer == NULL || netlogonDomain == NULL)
	return EINVAL;

    if ((ti->servername = strdup(netlogonServer)) == NULL)
	return ENOMEM;

    if ((ti->domainname = strdup(netlogonDomain)) == NULL) {
	free(ti->servername);
	return ENOMEM;
    }

    return 0;
}

/*
 *
 */

static int
netr_authenticate(void *ctx,
		  krb5_context context,
		  const NTLMRequest2 *ntq,
		  void *response_ctx,
		  void (response)(void *, const NTLMReply *ntp))
{
    struct ntlmnetr *c = ctx;
    OM_uint32 ret;
    NTLM_LOGON_REQ logonReq;
    krb5_data sessionkeydata;
    uint8_t sessionkey[16];
    uint32_t userFlags;
    int ntlm2;
    NTLMReply ntp;
    krb5_data pac;

    if (netlogonDomain == NULL || netlogonServer == NULL || ctx == NULL)
	return EINVAL;

    memset(&ntp, 0, sizeof(ntp));

    krb5_data_zero(&sessionkeydata);

    logonReq.Version = NTLM_LOGON_REQ_VERSION;
    logonReq.LogonDomainName = ntq->loginDomainName;
    logonReq.UserName = ntq->loginUserName;
    logonReq.Workstation = ntq->workstation;

    /*
     * From http://davenport.sourceforge.net/ntlm.html:
     *
     *  "Instead of sending the server challenge directly
     *  over the NetLogon pipe to the domain controller,
     *  the server sends the MD5 hash of the server challenge
     *  concatenated with the client nonce (lifted from the LM
     *  response field)."
     *
     * Unfortunately, the client doesn't give us any indication
     * whether it's using NTLMv1 with NTLM2 security or rather
     * NTLMv2. It appears we can only determine this from the
     * response length, which will be >24 for NTLMv2.
     */
    ntlm2 = (ntq->ntlmFlags & NTLM_NEG_NTLM2_SESSION) &&
            (ntq->lmChallengeResponse.length >= 8) &&
            (ntq->ntChallengeResponse.length == 24);

    if (ntlm2) {
        ret = heim_ntlm_calculate_ntlm2_sess_hash(ntq->lmChallengeResponse.data,
                                                  ntq->lmchallenge.data,
                                                  logonReq.LmChallenge);
        if (ret)
	    goto out;
    } else {
        memcpy(logonReq.LmChallenge, ntq->lmchallenge.data, 8);
        c->flags &= ~(LOGON_NTLMV2_ENABLED);
    }

    logonReq.NtChallengeResponseLength = ntq->ntChallengeResponse.length;
    logonReq.NtChallengeResponse = ntq->ntChallengeResponse.data;
    logonReq.LmChallengeResponseLength = ntq->lmChallengeResponse.length;
    logonReq.LmChallengeResponse = ntq->lmChallengeResponse.data;

    ret = nTLMLogon(&logonReq,
		    (uint8_t **)&pac.data,
		    &pac.length,
		    &ntp.user,
		    &ntp.domain,
		    sessionkey,
		    &userFlags);
    if (ret) {
	kdc_log(context, config, 1, "digest-request netr: failed user=%s\\%s DC status code %08x",
		ntq->loginDomainName,
		ntq->loginUserName,
		ret);
	goto out;
    }

    /* XXX copy into ntp */
    free(pac.data);

    if (ntlm2) {
        /* http://davenport.sourceforge.net/ntlm.html#theNtlm2SessionResponseUserSessionKey */
        heim_ntlm_derive_ntlm2_sess(sessionkey,
                                    ntq->lmChallengeResponse.data, 8,
                                    ntq->lmchallenge.data,
                                    sessionkey);
    }

    ntp.ntlmFlags = ntq->ntlmFlags;

    /*
     * If the client sent a NTLMv2 response (as opposed to a
     * NTLMv1 reponse with NTLM2 security), then we also need
     * to negotiate a NTLM2 session key.
     */
    if (userFlags & LOGON_NTLMV2_ENABLED)
	ntp.ntlmFlags |= NTLM_NEG_NTLM2_SESSION;

    if (ntq->ntlmFlags & NTLM_NEG_KEYEX) {
	struct ntlm_buf base, enc, sess;
	
	base.data = sessionkey;
	base.length = sizeof(sessionkey);
	enc.data = ntq->encryptedSessionKey.data;
	enc.length = ntq->encryptedSessionKey.length;
	
	ret = heim_ntlm_keyex_unwrap(&base, &enc, &sess);
	if (ret != 0)
	    goto out;
	if (sess.length != sizeof(sessionkey)) {
	    heim_ntlm_free_buf(&sess);
	    ret = EINVAL;
	    goto out;
	}
	memcpy(sessionkey, sess.data, sizeof(sessionkey));
	heim_ntlm_free_buf(&sess);
    }

    sessionkeydata.data = sessionkey;
    sessionkeydata.length = sizeof(sessionkey);
    ntp.sessionkey = &sessionkeydata;

    ntp.success = 1;

    response(response_ctx, &ntp);
    ret = 0;

out:
    log_complete(context, "netr", &ntp, ret, derive_version_ntq(ntq));

    if (ntp.user)
	free(ntp.user);
    if (ntp.domain)
	free(ntp.domain);
    return ret;
}

#endif

/*
 *
 */

struct ntlm_ftable backends[] = {
#ifdef HAVE_APPLE_NETLOGON
    {
	NULL,
	netr_init,
	NULL,
	netr_ti,
	netr_flags,
	netr_authenticate
    },
#endif
#ifdef HAVE_OPENDIRECTORY
    {
	NULL,
	od_init,
	NULL,
	NULL,
	od_flags,
	od_authenticate
    },
#endif
    {
	NULL,
	NULL,
	NULL,
	NULL,
	kdc_flags,
	kdc_authenticate
    },
    {
	NULL,
	NULL,
	NULL,
	NULL,
	guest_flags,
	guest_authenticate
    }
};

struct callback {
    heim_sipc_call cctx;
    heim_ipc_complete complete;
};

static void
complete_callback(void *ctx, const NTLMReply *ntp)
{
    struct callback *c = ctx;
    heim_idata rep;
    size_t size;
    int ret;
    
    ASN1_MALLOC_ENCODE(NTLMReply, rep.data, rep.length, ntp, &size, ret);
    if (ret)
	return;
    if (rep.length != size)
	abort();
    
    c->complete(c->cctx, ret, &rep);
    
    free(rep.data);
}

/*
 * Given the configuration, try to return the NTLM domain that is our
 * default DOMAIN.
 *
 * If we are not bound, pick the first in realm configuration that
 * matches the users preference.
 *
 * If we find no configuration, just return BUILTIN.
 */

static krb5_error_code
get_ntlm_domain(krb5_context context,
		krb5_kdc_configuration *config,
		const char *indomain,
		struct ntlm_targetinfo *ti)
{
    char *domain = NULL;
    krb5_error_code ret;
    unsigned int i;

    for (i = 0; i < sizeof(backends) / sizeof(backends[0]); i++) {
	if (backends[i].ti == NULL)
	    continue;

	memset(ti, 0, sizeof(*ti));
	ret = backends[i].ti(backends[i].ctx, ti);
	if (ret)
	    continue;

	if (indomain == NULL || strcmp(indomain, ti->domainname) == 0)
	    return 0;

	heim_ntlm_free_targetinfo(ti);
    }

    for (i = 0; i < config->num_db; i++) {
	if (config->db[i]->hdb_get_ntlm_domain == NULL)
	    continue;
	ret = config->db[i]->hdb_get_ntlm_domain(context,
						 config->db[i],
						 &domain);
	if (ret == 0 && domain)
	    break;
    }
    if (domain == NULL)
	domain = strdup("BUILTIN");

    memset(ti, 0, sizeof(*ti));

    /* make up a server name */
    {
	char local_hostname[MAXHOSTNAMELEN];
	char *p;

	if (gethostname(local_hostname, sizeof(local_hostname)) < 0) {
	    free(domain);
	    return EINVAL;
	}

	p = strchr(local_hostname, '.');
	if (p)
	    *p = '\0';
	strupr(local_hostname);

	ti->servername = strdup(local_hostname);
	if (ti->servername == NULL) {
	    free(domain);
	    return ENOMEM;
	}
    }
    ti->domainname = domain;

    return 0;
}


/*
 * process type1/init request
 */

static void
process_NTLMInit(krb5_context context,
		 NTLMInit *ni, 
		 heim_ipc_complete complete,
		 heim_sipc_call cctx)
{
    heim_idata rep = { 0, NULL };
    struct ntlm_targetinfo ti;
    NTLMInitReply ir;
    char *domain = NULL;
    size_t size, n;
    int ret = 0;
    
    memset(&ir, 0, sizeof(ir));
    memset(&ti, 0, sizeof(ti));
    
    kdc_log(context, config, 1, "digest-request: init request");
    
    ir.ntlmNegFlags = 0;
    for (n = 0; n < sizeof(backends) / sizeof(backends[0]); n++)
	ir.ntlmNegFlags |= backends[n].filter_flags(backends[n].ctx);

    if (ni->domain)
	domain = *ni->domain;
    
    ret = get_ntlm_domain(context, config, domain, &ti);
    if (ret)
	goto failed;
    
    kdc_log(context, config, 1, "digest-request: init return domain: %s server: %s",
	    ti.domainname, ti.servername);
    
    {
	struct ntlm_buf d;
	
	ret = heim_ntlm_encode_targetinfo(&ti, 1, &d);
	if (ret)
	    goto failed;
	ir.targetinfo.data = d.data;
	ir.targetinfo.length = d.length;
    }
    
    ASN1_MALLOC_ENCODE(NTLMInitReply, rep.data, rep.length, &ir, &size, ret);
    free_NTLMInitReply(&ir);
    if (ret)
	goto failed;
    if (rep.length != size)
	abort();
    
failed:
    if (ret)
	kdc_log(context, config, 1, "digest-request: %d", ret);
    
    heim_ntlm_free_targetinfo(&ti);

    (*complete)(cctx, ret, &rep);
    free(rep.data);
    
    return;
}

/*
 *
 */

static void
ntlm_service(void *ctx, const heim_idata *req,
	     const heim_icred cred,
	     heim_ipc_complete complete,
	     heim_sipc_call cctx)
{
    krb5_context context = ctx;
    static dispatch_once_t once;
    NTLMRequest2 ntq;
    NTLMInit ni;

    kdc_log(context, config, 1, "digest-request: uid=%d",
	    (int)heim_ipc_cred_get_uid(cred));
    
    if (heim_ipc_cred_get_uid(cred) != 0) {
	(*complete)(cctx, EPERM, NULL);
	return;
    }
    
    dispatch_once(&once, ^{
	size_t n;
	for (n = 0; n < sizeof(backends) / sizeof(backends[0]); n++)
	    if (backends[n].init)
		backends[n].init(context, &backends[n].ctx);
    });

    /* check if its a type1/init request */
    if (decode_NTLMInit(req->data, req->length, &ni, NULL) == 0) {
        process_NTLMInit(context, &ni, complete, cctx);
	free_NTLMInit(&ni);
    } else if (decode_NTLMRequest2(req->data, req->length, &ntq, NULL) == 0) {
	struct callback c = {
	    .complete = complete,
	    .cctx = cctx
	};
	size_t n;
	int ret = EPERM;
	
	for (n = 0; n < sizeof(backends) / sizeof(backends[0]); n++) {
	    ret = backends[n].authenticate(backends[n].ctx, context, &ntq, &c, complete_callback);
	    if (ret == 0)
		break;
	}
	free_NTLMRequest2(&ntq);
	if (ret)
	    (*complete)(cctx, ret, NULL);
    }
}


#endif

int
main(int argc, char **argv)
{
    krb5_context context;
    int ret;

    setprogname(argv[0]);

    ret = krb5_init_context(&context);
    if (ret)
	krb5_errx(context, 1, "krb5_init_context");

    ret = krb5_kdc_get_config(context, &config);
    if (ret)
	krb5_err(context, 1, ret, "krb5_kdc_default_config");

    kdc_openlog(context, "digest-service", config);

    ret = krb5_kdc_set_dbinfo(context, config);
    if (ret)
	krb5_err(context, 1, ret, "krb5_kdc_set_dbinfo");

#ifdef ENABLE_NTLM
#if __APPLE__
    {
	heim_sipc mach;
	heim_sipc_launchd_mach_init("org.h5l.ntlm-service",
				    ntlm_service, context, &mach);
    }
#endif
#endif
    heim_sipc_timeout(60);

    heim_ipc_main();
    return 0;
}
