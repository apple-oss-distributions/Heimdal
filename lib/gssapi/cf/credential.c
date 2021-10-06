/*-
 * Copyright (c) 2009 - 2011 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "mech_locl.h"
#include <heim_threads.h>

#include <Security/Security.h>
#include "krb5.h"

/**
 * Acquire a new initial credentials using long term credentials (password, certificate).
 *
 * Credentials acquired should be free-ed with gss_release_cred() or
 * destroyed with (removed from storage) gss_destroy_cred().
 *
 * Some mechanism types can not directly acquire or validate
 * credential (for example PK-U2U, SCRAM, NTLM or IAKERB), for those
 * mechanisms its instead the gss_init_sec_context() that will either acquire or
 * force validation of the credential.
 *
 * This function is blocking and should not be used on threads used for UI updates.
 *
 * @param desired_name name to use to acquire credential. Import the name using gss_import_name(). The type of the name has to be supported by the desired_mech used.
 *
 * @param desired_mech mechanism to use to acquire credential. GSS_C_NO_OID is not valid input and a mechanism must be selected. For example GSS_KRB5_MECHANISM, GSS_NTLM_MECHNISM or any other mechanisms supported by the implementation. See gss_indicate_mechs().
 *
 * @param attributes CFDictionary that contains how to acquire the credential, see below for examples
 *
 * @param output_cred_handle the resulting credential handle, value is set to GSS_C_NO_CREDENTIAL on failure.
 *
 * @param error an CFErrorRef returned in case of an error, that needs to be released with CFRelease() by the caller, input can be NULL.
 *
 * @returns a gss_error code, see the CFErrorRef passed back in error for the failure message.
 *
 * attributes must contains one of the following keys
 * * kGSSICPassword - CFStringRef password
 * * kGSSICCertificate - SecIdentityRef, SecCertificate, or CFDataRef[data of a Keychain Persistent Reference] to the certificate to use with PKINIT/PKU2U
 *
 * optional keys
 * * kGSSCredentialUsage - one of kGSS_C_INITIATE, kGSS_C_ACCEPT, kGSS_C_BOTH, default if not given is kGSS_C_INITIATE
 * * kGSSICVerifyCredential - validate the credential with a trusted source that there was no MITM
 * * kGSSICLKDCHostname - CFStringRef hostname of LKDC hostname
 * * kGSSICKerberosCacheName - CFStringRef name of cache that will be created (including type)
 * * kGSSICSiteName - CFStringRef name of site (you are authenticating too) used for load balancing in DNS in Kerberos)
 * * kGSSICAppIdentifierACL - CFArrayRef[CFStringRef] prefix of bundle ID allowed to access this credential
 * * kGSSICCreateNewCredential - CFBooleanRef if set caller wants to create a new credential and not overwrite a credential with the same name
 * * kGSSICAuthenticationContext - CFBooleanRef/YES to allow authentication UI, or LAContext to pass a pre-evaluated authentication context
 *
 * * kGSSICAppleSourceApp - CFDictionaryRef application we are performing this on behalf of (only applies to AppVPN)
 *
 * Keys for kGSSICAppleSourceApp dictionary:
 *
 * - kGSSICAppleSourceAppAuditToken - audit token of process this is
 *  		preformed on behalf of, the audit_token_t is wrapped
 *  		in a CFDataRef.
 * - kGSSICAppleSourceAppPID - PID in a CFNumberRef of process this is
 *              preformed on behalf of
 * - kGSSICAppleSourceAppUUID - UUID of the application
 * - kGSSICAppleSourceAppSigningIdentity - bundle/signing identity of the application
 *
 *	  
 * @ingroup gssapi
 */

OM_uint32 GSSAPI_LIB_FUNCTION
gss_aapl_initial_cred(__nonnull const gss_name_t desired_name,
		      __nonnull gss_const_OID desired_mech,
		      __nullable CFDictionaryRef attributes,
		      __nonnull gss_cred_id_t * __nullable output_cred_handle,
		      __nullable CFErrorRef *__nullable error)
{
    OM_uint32 major_status, minor_status;
    gss_buffer_desc credential;
    CFStringRef usage;
    CFTypeRef password, certificate;
    gss_cred_usage_t cred_usage = GSS_C_INITIATE;
    gss_const_OID cred_type;
    void *cred_value;

    credential.value = NULL;
    credential.length = 0;

    HEIM_WARN_BLOCKING("gss_aapl_initial_cred", warn_once);

    if (error)
	*error = NULL;

    if (desired_mech == GSS_C_NO_OID)
	return GSS_S_BAD_MECH;
    if (desired_name == GSS_C_NO_NAME)
	return GSS_S_BAD_NAME;

    if (output_cred_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;

    /* require password or certificate */
    password = CFDictionaryGetValue(attributes, kGSSICPassword);
    certificate = CFDictionaryGetValue(attributes, kGSSICCertificate);
    if (password == NULL && certificate == NULL) {
	return GSS_S_CALL_INACCESSIBLE_READ;
    }

    /* check usage */
    usage = CFDictionaryGetValue(attributes, kGSSCredentialUsage);
    if (usage && CFGetTypeID(usage) == CFStringGetTypeID()) {
	if (CFStringCompare(usage, kGSS_C_INITIATE, 0) == kCFCompareEqualTo)
	    cred_usage = GSS_C_INITIATE;
	else if (CFStringCompare(usage, kGSS_C_ACCEPT, 0) == kCFCompareEqualTo)
	    cred_usage = GSS_C_ACCEPT;
	else if (CFStringCompare(usage, kGSS_C_BOTH, 0) == kCFCompareEqualTo)
	    cred_usage = GSS_C_BOTH;
	else
	    return GSS_S_FAILURE;
    }

    if (gss_oid_equal(desired_mech, GSS_KRB5_MECHANISM)) {

	cred_value = (void *)attributes;
	cred_type = GSS_C_CRED_HEIMBASE;
	
    } else if (password && CFGetTypeID(password) == CFStringGetTypeID()) {
	char *str = rk_cfstring2cstring(password);
	if (str == NULL)
	    return GSS_S_FAILURE;

	credential.value = str;
	credential.length = strlen(str);
	cred_value = &credential;
	cred_type = GSS_C_CRED_PASSWORD;

    } else if (password && CFGetTypeID(password) == CFDataGetTypeID()) {
	credential.value = malloc(CFDataGetLength(password));
	if (credential.value == NULL)
	    return GSS_S_FAILURE;

	credential.length = CFDataGetLength(password);
	memcpy(credential.value, CFDataGetBytePtr(password), CFDataGetLength(password));

	cred_value = &credential;
	cred_type = GSS_C_CRED_PASSWORD;
    } else if (certificate && CFGetTypeID(certificate) == SecIdentityGetTypeID()) {
	cred_value = rk_UNCONST(certificate);
	cred_type = GSS_C_CRED_SecIdentity;
    } else if (certificate && CFGetTypeID(certificate) == SecCertificateGetTypeID()) {
	cred_value = rk_UNCONST(certificate);
	cred_type = GSS_C_CRED_SecIdentity;
    } else
	return GSS_S_FAILURE;

    major_status = gss_acquire_cred_ext(&minor_status,
					desired_name,
					cred_type,
					cred_value,
					GSS_C_INDEFINITE,
					desired_mech,
					cred_usage,
					output_cred_handle);
    if (credential.length) {
	memset(credential.value, 0, credential.length);
	free(credential.value);
    }
	
    if (major_status && error) {
	*error = _gss_mg_create_cferror(major_status, minor_status, desired_mech);
	return major_status;
    }
    
    return major_status;
}

/**
 * Change pasword for a gss name
 *
 * @param name name to change password for
 * @param mech mechanism to use
 * @param attributes old and new password (kGSSChangePasswordOldPassword and kGSSChangePasswordNewPassword) and other attributes.
 * @param error if not NULL, error might be set case function doesn't
 *       return GSS_S_COMPLETE, in that case is must be released with
 *       CFRelease().
 *
 * @returns returns GSS_S_COMPLETE on success, error might be set if passed in.
 *
 * @ingroup gssapi
 */

OM_uint32 GSSAPI_LIB_FUNCTION
gss_aapl_change_password(__nonnull const gss_name_t name,
			 __nonnull gss_const_OID mech,
			 __nonnull CFDictionaryRef attributes,
			 __nullable CFErrorRef *__nullable error)
{
    struct _gss_mechanism_name *mn = NULL;
    char *oldpw = NULL, *newpw = NULL;
    OM_uint32 maj_stat, min_stat;
    gssapi_mech_interface m;
    CFStringRef old, new;

    _gss_load_mech();

    m = __gss_get_mechanism(mech);
    if (m == NULL) {
	maj_stat = GSS_S_BAD_MECH;
	min_stat = 0;
	goto out;
    }

    if (m->gm_aapl_change_password == NULL) {
	maj_stat = GSS_S_UNAVAILABLE;
	min_stat = 0;
	goto out;
    }

    maj_stat = _gss_find_mn(&min_stat, (struct _gss_name *)name, mech, &mn);
    if (maj_stat != GSS_S_COMPLETE)
	goto out;

    old = CFDictionaryGetValue(attributes, kGSSChangePasswordOldPassword);
    new = CFDictionaryGetValue(attributes, kGSSChangePasswordNewPassword);

    heim_assert(old != NULL, "old password missing");
    heim_assert(new != NULL, "new password missing");

    oldpw = rk_cfstring2cstring(old);
    newpw = rk_cfstring2cstring(new);

    if (oldpw == NULL || newpw == NULL) {
	maj_stat = GSS_S_FAILURE;
	min_stat = 0;
	goto out;
    }

    maj_stat = m->gm_aapl_change_password(&min_stat,
					  mn->gmn_name,
					  oldpw, newpw);
    if (maj_stat)
	_gss_mg_error(m, min_stat);

 out:
    if (maj_stat && error)
	*error = _gss_mg_create_cferror(maj_stat, min_stat, mech);

    if (oldpw) {
	memset(oldpw, 0, strlen(oldpw));
	free(oldpw);
    }
    if (newpw) {
	memset(newpw, 0, strlen(newpw));
	free(newpw);
    }

    return maj_stat;
}

/**
 * Returns a copy of the UUID of the GSS credential
 *
 * @param credential credential
 *
 * @returns CFUUIDRef that can be used to turn into a credential,
 * normal CoreFoundaton rules for rules applies so the CFUUIDRef needs
 * to be released.
 *
 * @ingroup gssapi
 */

__nullable CFUUIDRef
GSSCredentialCopyUUID(gss_cred_id_t __nonnull credential)
{
    OM_uint32 major, minor;
    gss_buffer_set_t dataset = GSS_C_NO_BUFFER_SET;
    krb5_error_code ret;
    krb5_uuid uuid;
    CFUUIDBytes cfuuid;

    major = gss_inquire_cred_by_oid(&minor, credential, GSS_C_NT_UUID, &dataset);
    if (major || dataset->count != 1) {
	gss_release_buffer_set(&minor, &dataset);
	return NULL;
    }
	    
    if (dataset->elements[0].length != 36) {
	gss_release_buffer_set(&minor, &dataset);
	return NULL;
    }

    ret = krb5_string_to_uuid(dataset->elements[0].value, uuid);
    gss_release_buffer_set(&minor, &dataset);
    if (ret)
	return NULL;
	
    memcpy(&cfuuid, uuid, sizeof(uuid));

    return CFUUIDCreateFromUUIDBytes(NULL, cfuuid);
}

/**
 * Returns a GSS credential for a given UUID if the credential exists.
 *
 * @param uuid the UUID of the credential to fetch
 *
 * @returns a gss_cred_id_t, normal CoreFoundaton rules for rules
 * applies so the CFUUIDRef needs to be released with either CFRelease() or gss_release_name().
 *
 * @ingroup gssapi
 */

__nullable gss_cred_id_t GSSAPI_LIB_FUNCTION
GSSCreateCredentialFromUUID(__nonnull CFUUIDRef uuid)
{
    OM_uint32 min_stat, maj_stat;
    gss_cred_id_t cred;
    CFStringRef name;
    gss_name_t gname;

    name = CFUUIDCreateString(NULL, uuid);
    if (name == NULL)
	return NULL;
    
    gname = GSSCreateName(name, GSS_C_NT_UUID, NULL);
    CFRelease(name);
    if (gname == NULL)
	return NULL;

    maj_stat = gss_acquire_cred(&min_stat, gname, GSS_C_INDEFINITE, NULL,
				GSS_C_INITIATE, &cred, NULL, NULL);
    gss_release_name(&min_stat, &gname);
    if (maj_stat != GSS_S_COMPLETE)
	return NULL;

    return cred;
}

static CFStringRef
CopyFoldString(CFStringRef host)
{
    CFMutableStringRef string = CFStringCreateMutableCopy(NULL, 0, host);
    static dispatch_once_t once;
    static CFLocaleRef locale;
    dispatch_once(&once, ^{
	    locale = CFLocaleCreate(NULL, CFSTR("C"));
	});
    CFStringFold(string, kCFCompareCaseInsensitive, locale);
    return string;
}

static bool
FoldedHostName(CFStringRef stringOrURL, CFStringRef *scheme, CFStringRef *host, CFStringRef *path)
{
    CFRange range;

    *scheme = NULL;
    *host = NULL;
    *path = NULL;

    range = CFStringFind(stringOrURL, CFSTR(":"), 0);
    if (range.location != kCFNotFound) {
	CFURLRef url;

	url = CFURLCreateWithString(NULL, stringOrURL, NULL);
	if (url) {
	    CFStringRef hn = CFURLCopyHostName(url);
	    if (hn == NULL) {
		*host = CFSTR("");
	    } else {
		*host = CopyFoldString(hn);
		CFRelease(hn);
		if (*host == NULL) {
		    CFRelease(url);
		    return false;
		}
	    }

	    *scheme = CFURLCopyScheme(url);
	    if (*scheme == NULL)
		*scheme = CFSTR("");

	    *path = CFURLCopyPath(url);
	    if (*path == NULL || CFStringCompare(*path, CFSTR(""), 0) == kCFCompareEqualTo) {
		if (*path)
		    CFRelease(*path);
		*path = CFSTR("/");
	    }
	    CFRelease(url);
	}
    }

    if (*host == NULL) {
	*host = CopyFoldString(stringOrURL);
	if (*scheme)
	    CFRelease(*scheme);
	*scheme = CFSTR("any");
	*path = CFSTR("/");
    }

    return true;
}

/*
 *
 */

void
GSSRuleAddMatch(__nonnull CFMutableDictionaryRef rules, __nonnull CFStringRef host, __nonnull CFStringRef value)
{
    CFStringRef scheme = NULL, hostname = NULL, path = NULL;
    CFMutableDictionaryRef match;

    if (!FoldedHostName(host, &scheme, &hostname, &path))
	return;

    match = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (match == NULL)
	goto out;

    CFDictionarySetValue(match, CFSTR("scheme"), scheme);
    CFDictionarySetValue(match, CFSTR("path"), path);
    CFDictionarySetValue(match, CFSTR("value"), value);
    
    CFArrayRef array = CFDictionaryGetValue(rules, hostname);
    CFMutableArrayRef mutable;

    if (array) {
	mutable = CFArrayCreateMutableCopy(NULL, 0, array);
    } else {
	mutable = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    }
    if (mutable) {
		
	CFIndex n, count = CFArrayGetCount(mutable);

	for (n = 0; n < count; n++) {
	    CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(mutable, n);
	    CFStringRef p = CFDictionaryGetValue(item, CFSTR("path"));
	    CFStringRef s = CFDictionaryGetValue(item, CFSTR("scheme"));
	    
	    if (CFStringCompare(s, scheme, kCFCompareCaseInsensitive) == kCFCompareLessThan)
		continue;
	    
	    if (CFStringHasPrefix(path, p)) {
		CFArrayInsertValueAtIndex(mutable, n, match);
		break;
	    }
	}
	if (n >= count)
	    CFArrayAppendValue(mutable, match);
	
	CFDictionarySetValue(rules, hostname, mutable);
	CFRelease(mutable);
    }

out:
    CFRelease(scheme);
    CFRelease(hostname);
    CFRelease(path);
    if (match)
	CFRelease(match);
}

/*
 * host is a URL string or hostname string
 */

__nullable CFStringRef
GSSRuleGetMatch(__nonnull CFDictionaryRef rules, __nonnull CFStringRef hostname)
{
    CFStringRef scheme = NULL, hostFolded = NULL, path = NULL;
    CFTypeRef result = NULL;
    const char *p;

    if (!FoldedHostName(hostname, &scheme, &hostFolded, &path))
	return NULL;

    char *host = rk_cfstring2cstring(hostFolded);
    CFRelease(hostFolded);
    if (host == NULL) {
	CFRelease(path);
	return NULL;
    }
    
    if (host[0] == '\0') {
	CFRelease(scheme);
	free(host);
	CFRelease(path);
	return NULL;
    }
    
    for (p = host; p != NULL && result == NULL; p = strchr(p + 1, '.')) {
	CFStringRef partial = CFStringCreateWithCString(NULL, p, kCFStringEncodingUTF8);
	CFArrayRef array = (CFArrayRef)CFDictionaryGetValue(rules, partial);

	CFRelease(partial);

	if (array) {
	    CFIndex n, count = CFArrayGetCount(array);

	    for (n = 0; n < count && result == NULL; n++) {
		CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(array, n);

		CFStringRef matchScheme = CFDictionaryGetValue(item, CFSTR("scheme"));
		if (CFStringCompare(scheme, matchScheme, kCFCompareCaseInsensitive) != kCFCompareEqualTo &&
		    CFStringCompare(CFSTR("any"), matchScheme, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
		    continue;

		CFStringRef matchPath = CFDictionaryGetValue(item, CFSTR("path"));
		if (CFStringHasPrefix(path, matchPath))
		    result = CFDictionaryGetValue(item, CFSTR("value"));

	    }
	}
    }
    CFRelease(scheme);
    free(host);
    CFRelease(path);
    return result;
}

/**
 * Create a GSS name from a buffer and type.
 *
 * @param name name buffer describing a credential, can be either a CFDataRef or CFStringRef of a name.
 * @param name_type on OID of the GSS_C_NT_* OIDs constants specifiy the name type.
 * @param error if an error happen, this may be set to a CFErrorRef describing the failure futher.
 *
 * @returns returns gss_name_t or NULL on failure. Must be freed using gss_release_name() or CFRelease(). Follows CoreFoundation Create/Copy rule.
 *
 * @ingroup gssapi
 */

__nullable gss_name_t
GSSCreateName(__nonnull CFTypeRef name, __nonnull gss_const_OID name_type, __nullable CFErrorRef *__nullable error)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc buffer;
    int free_data = 0;
    gss_name_t n;

    if (error)
	*error = NULL;

    if (CFGetTypeID(name) == CFStringGetTypeID()) {
	buffer.value = rk_cfstring2cstring(name);
	if (buffer.value == NULL)
	    return GSS_S_FAILURE;
	buffer.length = strlen((char *)buffer.value);
	free_data = 1;
    } else if (CFGetTypeID(name) == CFDataGetTypeID()) {
	buffer.value = (void *)CFDataGetBytePtr(name);
	buffer.length = (OM_uint32)CFDataGetLength(name);
    } else {
	return GSS_C_NO_NAME;
    }

    maj_stat = gss_import_name(&min_stat, &buffer, name_type, &n);

    if (free_data)
	free(buffer.value);

    if (maj_stat)
	return GSS_C_NO_NAME;

    return n;
}

/**
 * Copy the name describing the credential
 *
 * @param cred the credential to get the name from
 *
 * @returns returns gss_name_t or NULL on failure. Must be freed using gss_release_name() or CFRelease(). Follows CoreFoundation Create/Copy rule.
 *
 * @ingroup gssapi
 */

__nullable gss_name_t
GSSCredentialCopyName(__nonnull gss_cred_id_t cred)
{
    OM_uint32 major, minor;
    gss_name_t name;
                
    major = gss_inquire_cred(&minor, cred, &name, NULL, NULL, NULL);
    if (major != GSS_S_COMPLETE)
	return NULL;
	
    return name;
}

/**
 * Return the lifetime (in seconds) left of the credential.
 *
 * @param cred the credential to get the name from
 *
 * @returns the lifetime of the credentials. 0 on failure and
 * GSS_C_INDEFINITE on credentials that never expire.
 *
 * @ingroup gssapi
 */

OM_uint32
GSSCredentialGetLifetime(__nonnull gss_cred_id_t cred)
{
    OM_uint32 maj_stat, min_stat;
    OM_uint32 lifetime;
                
    maj_stat = gss_inquire_cred(&min_stat, cred, NULL, &lifetime, NULL, NULL);
    if (maj_stat != GSS_S_COMPLETE)
	return 0;
	
    return lifetime;
}

/**
 * Returns a string that is suitable for displaying to user, must not
 * be used for verify subjects on an ACLs.
 *
 * @param name to get a display strings from
 *
 * @returns a string that is printable. Follows CoreFoundation Create/Copy rule.
 *
 * @ingroup gssapi
 */

__nullable CFStringRef
GSSNameCreateDisplayString(__nonnull gss_name_t name)
{
    OM_uint32 maj_stat, min_stat;
    gss_buffer_desc buffer;
    CFStringRef str;

    maj_stat = gss_display_name(&min_stat, name, &buffer, NULL);
    if (maj_stat != GSS_S_COMPLETE)
	return NULL;

    str = CFStringCreateWithBytes(NULL, (const UInt8 *)buffer.value, buffer.length, kCFStringEncodingUTF8, false);
    gss_release_buffer(&min_stat, &buffer);

    return str;
}

/*
 * Create a CFErrorRef from GSS-API major and minor status code.
 *
 * @param major_status Major status code returned by the funcation that failed
 * @param major_status Major status code returned by the funcation that failed
 * @param mech Mechanism passed in, if not available GSS_C_NO_OID should be used
 *
 * @returns a CFErrorRef in the domain org.h5l.GSS domain
 *
 * @ingroup gssapi
 */

__nullable CFErrorRef
GSSCreateError(__nonnull gss_const_OID mech,
	       OM_uint32 major_status,
	       OM_uint32 minor_status)
{
    return _gss_mg_create_cferror(major_status,  minor_status, mech);
}


/* deprecated */
OM_uint32
GSSCredGetLifetime(__nonnull gss_cred_id_t cred)
{
    return GSSCredentialGetLifetime(cred);
}

gss_name_t
GSSCredCopyName(__nonnull gss_cred_id_t cred)
{
    return GSSCredentialCopyName(cred);
}

