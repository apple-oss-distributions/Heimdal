/*
 * Copyright (c) 1997 - 2002 Kungliga Tekniska Högskolan
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

#ifdef __osf__
/* hate */
struct rtentry;
struct mbuf;
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <ifaddrs.h>

static krb5_error_code
gethostname_fallback (krb5_context context, krb5_addresses *res)
{
    krb5_error_code ret;
    char hostname[MAXHOSTNAMELEN];
    struct hostent *hostent;

    if (gethostname (hostname, sizeof(hostname))) {
	ret = errno;
	krb5_set_error_message(context, ret, "gethostname: %s", strerror(ret));
	return ret;
    }
    hostent = roken_gethostbyname (hostname);
    if (hostent == NULL) {
	ret = errno;
	krb5_set_error_message (context, ret, "gethostbyname %s: %s",
				hostname, strerror(ret));
	return ret;
    }
    res->len = 1;
    res->val = malloc (sizeof(*res->val));
    if (res->val == NULL) {
	krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	return ENOMEM;
    }
    res->val[0].addr_type = hostent->h_addrtype;
    res->val[0].address.data = NULL;
    res->val[0].address.length = 0;
    ret = krb5_data_copy (&res->val[0].address,
			  hostent->h_addr,
			  hostent->h_length);
    if (ret) {
	free (res->val);
	return ret;
    }
    return 0;
}

enum {
    LOOP            = 1,	/* do include loopback addrs */
    LOOP_IF_NONE    = 2,	/* include loopback addrs if no others */
    EXTRA_ADDRESSES = 4,	/* include extra addresses */
    SCAN_INTERFACES = 8		/* scan interfaces for addresses */
};

/*
 * Try to figure out the addresses of all configured interfaces with a
 * lot of magic ioctls.
 */

static krb5_error_code
find_all_addresses (krb5_context context, krb5_addresses *res, int flags)
{
    struct sockaddr sa_zero;
    struct ifaddrs *ifa0, *ifa;
    krb5_error_code ret = ENXIO;
    unsigned int num, idx;
    krb5_addresses ignore_addresses;

    if (getifaddrs(&ifa0) == -1) {
	ret = errno;
	krb5_set_error_message(context, ret, "getifaddrs: %s", strerror(ret));
	return (ret);
    }

    memset(&sa_zero, 0, sizeof(sa_zero));

    /* First, count all the ifaddrs. */
    for (ifa = ifa0, num = 0; ifa != NULL; ifa = ifa->ifa_next, num++)
	/* nothing */;

    if (num == 0) {
	freeifaddrs(ifa0);
	krb5_set_error_message(context, ENXIO, N_("no addresses found", ""));
	return (ENXIO);
    }

    if (flags & EXTRA_ADDRESSES) {
	/* we'll remove the addresses we don't care about */
	ret = krb5_get_ignore_addresses(context, &ignore_addresses);
	if(ret)
	    return ret;
    }

    /* Allocate storage for them. */
    res->val = calloc(num, sizeof(*res->val));
    if (res->val == NULL) {
	krb5_free_addresses(context, &ignore_addresses);
	freeifaddrs(ifa0);
	krb5_set_error_message(context, ENOMEM, N_("malloc: out of memory", ""));
	return ENOMEM;
    }

    /* Now traverse the list. */
    for (ifa = ifa0, idx = 0; ifa != NULL; ifa = ifa->ifa_next) {
	if ((ifa->ifa_flags & IFF_UP) == 0)
	    continue;
	if (ifa->ifa_addr == NULL)
	    continue;
	if (memcmp(ifa->ifa_addr, &sa_zero, sizeof(sa_zero)) == 0)
	    continue;
	if (krb5_sockaddr_uninteresting(ifa->ifa_addr))
	    continue;
	if (krb5_sockaddr_is_loopback(ifa->ifa_addr) && (flags & LOOP) == 0)
	    /* We'll deal with the LOOP_IF_NONE case later. */
	    continue;

	ret = krb5_sockaddr2address(context, ifa->ifa_addr, &res->val[idx]);
	if (ret) {
	    /*
	     * The most likely error here is going to be "Program
	     * lacks support for address type".  This is no big
	     * deal -- just continue, and we'll listen on the
	     * addresses who's type we *do* support.
	     */
	    continue;
	}
	/* possibly skip this address? */
	if((flags & EXTRA_ADDRESSES) &&
	   krb5_address_search(context, &res->val[idx], &ignore_addresses)) {
	    krb5_free_address(context, &res->val[idx]);
	    flags &= ~LOOP_IF_NONE; /* we actually found an address,
                                       so don't add any loop-back
                                       addresses */
	    continue;
	}

	idx++;
    }

    /*
     * If no addresses were found, and LOOP_IF_NONE is set, then find
     * the loopback addresses and add them to our list.
     */
    if ((flags & LOOP_IF_NONE) != 0 && idx == 0) {
	for (ifa = ifa0; ifa != NULL; ifa = ifa->ifa_next) {
	    if ((ifa->ifa_flags & IFF_UP) == 0)
		continue;
	    if (ifa->ifa_addr == NULL)
		continue;
	    if (memcmp(ifa->ifa_addr, &sa_zero, sizeof(sa_zero)) == 0)
		continue;
	    if (krb5_sockaddr_uninteresting(ifa->ifa_addr))
		continue;
	    if (!krb5_sockaddr_is_loopback(ifa->ifa_addr))
		continue;
	    if ((ifa->ifa_flags & IFF_LOOPBACK) == 0)
		/* Presumably loopback addrs are only used on loopback ifs! */
		continue;
	    ret = krb5_sockaddr2address(context,
					ifa->ifa_addr, &res->val[idx]);
	    if (ret)
		continue; /* We don't consider this failure fatal */
	    if((flags & EXTRA_ADDRESSES) &&
	       krb5_address_search(context, &res->val[idx],
				   &ignore_addresses)) {
		krb5_free_address(context, &res->val[idx]);
		continue;
	    }
	    idx++;
	}
    }

    if (flags & EXTRA_ADDRESSES)
	krb5_free_addresses(context, &ignore_addresses);
    freeifaddrs(ifa0);
    if (ret) {
	free(res->val);
	res->val = NULL;
    } else
	res->len = idx;        /* Now a count. */
    return (ret);
}

static krb5_error_code
get_addrs_int (krb5_context context, krb5_addresses *res, int flags)
{
    krb5_error_code ret = -1;

    res->len = 0;
    res->val = NULL;

    if (flags & SCAN_INTERFACES) {
	ret = find_all_addresses (context, res, flags);
	if(ret || res->len == 0)
	    ret = gethostname_fallback (context, res);
    } else {
	ret = 0;
    }

    if(ret == 0 && (flags & EXTRA_ADDRESSES)) {
	krb5_addresses a;
	/* append user specified addresses */
	ret = krb5_get_extra_addresses(context, &a);
	if(ret) {
	    krb5_free_addresses(context, res);
	    return ret;
	}
	ret = krb5_append_addresses(context, res, &a);
	if(ret) {
	    krb5_free_addresses(context, res);
	    return ret;
	}
	krb5_free_addresses(context, &a);
    }
    if(res->len == 0) {
	free(res->val);
	res->val = NULL;
    }
    return ret;
}

/*
 * Try to get all addresses, but return the one corresponding to
 * `hostname' if we fail.
 *
 * Only include loopback address if there are no other.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_all_client_addrs (krb5_context context, krb5_addresses *res)
{
    int flags = LOOP_IF_NONE | EXTRA_ADDRESSES;

    if (context->scan_interfaces)
	flags |= SCAN_INTERFACES;

    return get_addrs_int (context, res, flags);
}

/*
 * Try to get all local addresses that a server should listen to.
 * If that fails, we return the address corresponding to `hostname'.
 */

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_all_server_addrs (krb5_context context, krb5_addresses *res)
{
    return get_addrs_int (context, res, LOOP | SCAN_INTERFACES);
}

KRB5_LIB_FUNCTION krb5_error_code KRB5_LIB_CALL
krb5_get_all_any_addrs(krb5_context context, krb5_addresses *res)
{
    krb5_error_code ret;
    krb5_addresses as;
    krb5_address a;
    struct sockaddr_storage ss;
    krb5_socklen_t sa_size;
    unsigned int n;
    int types[] = {
	AF_INET6,
	AF_INET
    };

    memset(&a, 0, sizeof(a));

    res->len = 0;
    res->val = NULL;

    for (n = 0; n < sizeof(types)/sizeof(types[0]); n++) {
	sa_size = sizeof(ss);
	ret = krb5_anyaddr(context, types[n], (struct sockaddr *)&ss, &sa_size, 0);
	if (ret)
	    continue;

	ret = krb5_sockaddr2address(context, (struct sockaddr *)&ss, &a);
	if (ret)
	    continue;

	as.val = &a;
	as.len = 1;
	ret = krb5_append_addresses(context, res, &as);
	krb5_free_address(context, &a);
	if(ret) {
	    krb5_free_addresses(context, res);
	    return ret;
	}
    }
    if (res->len == 0) {
	krb5_set_error_message(context, ENXIO, N_("no addresses found", ""));
	return (ENXIO);
    }
    return 0;
}

/*
 * Get currently configured address families on the local device
 */

static const struct {
    int af;
    krb5_af_flags kaf;
} af2kaf[] = {
    {
	KRB5_ADDRESS_INET,
	KRB5_AF_FLAG_INET,
    }, {
	KRB5_ADDRESS_INET6,
	KRB5_AF_FLAG_INET6,
    }
};


krb5_af_flags
_krb5_get_supported_af(krb5_context context)
{
    krb5_af_flags kaf = 0;
    krb5_addresses res;
    krb5_error_code ret;
    unsigned n, m;

    memset(&res, 0, sizeof(res));

    ret = find_all_addresses(context, &res, SCAN_INTERFACES);
    if (ret)
	return 0;

    for (n = 0; n < res.len; n++) {
	int af = res.val[n].addr_type;
	for (m = 0; m < sizeof(af2kaf)/sizeof(af2kaf[0]); m++) {
	    if (af == af2kaf[m].af) {
		kaf |= af2kaf[m].kaf;
		break;
	    }
	}
    }
    krb5_free_addresses(context, &res);

    return kaf;
}
