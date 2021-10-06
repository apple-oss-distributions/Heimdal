/*
 * Copyright (c) 1997-2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 - 2010 Apple Inc. All rights reserved.
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

/* $Id$ */

#ifndef __KRB5_LOCL_H__
#define __KRB5_LOCL_H__

#include <config.h>

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <krb5-types.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if defined(HAVE_SYS_IOCTL_H) && SunOS != 40
#include <sys/ioctl.h>
#endif
#ifdef HAVE_PWD_H
#undef _POSIX_PTHREAD_SEMANTICS
/* This gets us the 5-arg getpwnam_r on Solaris 9.  */
#define _POSIX_PTHREAD_SEMANTICS
#include <pwd.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef _AIX
struct ether_addr;
struct mbuf;
struct sockaddr_dl;
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef HAVE_NOTIFY_H
#include <notify.h>
#endif

#include "heimbase.h"
#include "heimbasepriv.h"
#include "heimbase_impl.h"

#include <com_err.h>

#include <heimbase.h>

#define HEIMDAL_TEXTDOMAIN "heimdal_krb5"

#ifdef LIBINTL
#include <libintl.h>
#define N_(x,y) dgettext(HEIMDAL_TEXTDOMAIN, x)
#else
#define N_(x,y) (x)
#define bindtextdomain(package, localedir)
#endif


#ifdef HAVE_CRYPT_H
#undef des_encrypt
#define des_encrypt wingless_pigs_mostly_fail_to_fly
#include <crypt.h>
#undef des_encrypt
#endif

#ifdef HAVE_DOOR_CREATE
#include <door.h>
#endif

#include <roken.h>
#include <parse_time.h>
#include <base64.h>

#include <wind.h>

#define HC_DEPRECATED_CRYPTO
#include "crypto-headers.h"


#include <krb5_asn1.h>

#if __APPLE__

#include <xpc/xpc.h>
#if !TARGET_OS_SIMULATOR && !TARGET_OS_OSX
#include <NEHelperClient.h>
#include <nw/private.h>
#include <ne_session.h>
#endif /* !TARGET_OS_SIMULATOR && !TARGET_OS_OSX */

#endif /* __APPLE__ */


struct send_to_kdc;

/* XXX glue for pkinit */
struct hx509_certs_data;
struct hx509_cert_data;
struct hx509_query_data;
struct krb5_pk_identity;
struct krb5_pk_cert;
struct key_data;
struct ContentInfo;
struct AlgorithmIdentifier;
typedef struct krb5_pk_init_ctx_data *krb5_pk_init_ctx;
struct krb5_dh_moduli;
struct _krb5_srv_query_ctx;
struct krb5_fast_state;
struct _krb5_srp_group;
struct _krb5_srp;

/* v4 glue */
struct _krb5_krb_auth_data;

#include <der.h>

#include <krb5.h>
#include <krb5_err.h>
#include <asn1_err.h>
#ifdef PKINIT
#include <heimbase.h>
#include <hx509.h>
#endif

#include "heim_threads.h"
#include "crypto.h"
#include "dns_sd.h"

#include <krb5-private.h>

extern const char _krb5_wellknown_lkdc[];

#define ALLOC(X, N) (X) = calloc((N), sizeof(*(X)))
#define ALLOC_SEQ(X, N) do { (X)->len = (N); ALLOC((X)->val, (N)); } while(0)

#ifndef __func__
#define __func__ "unknown-function"
#endif

#define krb5_einval(context, argnum) _krb5_einval((context), __func__, (argnum))

#ifndef PATH_SEP
#define PATH_SEP ":"
#endif

/* should this be public? */
#define KEYTAB_DEFAULT "FILE:" SYSCONFDIR "/krb5.keytab"
#define KEYTAB_DEFAULT_MODIFY "FILE:" SYSCONFDIR "/krb5.keytab"


#define MODULI_FILE SYSCONFDIR "/krb5.moduli"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif


#define KRB5_BUFSIZ 2048

typedef enum {
    KRB5_INIT_CREDS_TRISTATE_UNSET = 0,
    KRB5_INIT_CREDS_TRISTATE_TRUE,
    KRB5_INIT_CREDS_TRISTATE_FALSE
} krb5_get_init_creds_tristate;

struct _krb5_get_init_creds_opt_private {
    int refcount;
    /* ENC_TIMESTAMP */
    const char *password;
    krb5_s2k_proc key_proc;
    /* PA_PAC_REQUEST */
    krb5_get_init_creds_tristate req_pac;
    /* PKINIT */
    krb5_pk_init_ctx pk_init_ctx;
    krb5_get_init_creds_tristate addressless;
    int flags;
#define KRB5_INIT_CREDS_DONE					1
#define KRB5_INIT_CREDS_CANONICALIZE				2
#define KRB5_INIT_CREDS_NO_C_CANON_CHECK			4
#define KRB5_INIT_CREDS_NO_C_NO_EKU_CHECK			8
#define KRB5_INIT_CREDS_PKU2U					16
#define KRB5_INIT_CREDS_PKINIT_KX_VALID				32
#define KRB5_INIT_CREDS_PKINIT_NO_KRBTGT_OTHERNAME_CHECK	64
    struct {
        krb5_gic_process_last_req func;
        void *ctx;
    } lr;
};

typedef uint32_t krb5_enctype_set;

typedef struct krb5_context_data {
    struct heim_base_uniq base;
    krb5_enctype *etypes;
    krb5_enctype *etypes_des;/* deprecated */
    krb5_enctype *as_etypes;
    krb5_enctype *tgs_etypes;
    krb5_enctype *permitted_enctypes;
    heim_array_t default_realms;
    time_t max_skew;
    time_t kdc_timeout;
    time_t host_timeout;
    unsigned max_retries;
    int32_t kdc_sec_offset;
    int32_t kdc_usec_offset;
    char **config_files;
    time_t last_config_update;
    krb5_config_section *cf;
    struct et_list *et_list;
    struct krb5_log_facility *warn_dest;
    struct krb5_log_facility *debug_dest;
    const krb5_cc_ops **cc_ops;
    int num_cc_ops;
    const char *http_proxy;
    const char *time_fmt;
    krb5_boolean log_utc;
    const char *default_keytab;
    const char *default_keytab_modify;
    krb5_boolean use_admin_kdc;
    krb5_addresses *extra_addresses;
    krb5_boolean scan_interfaces;	/* `ifconfig -a' */
    krb5_boolean srv_lookup;		/* do SRV lookups */
    krb5_boolean srv_try_txt;		/* try TXT records also */
    int32_t fcache_vno;			/* create cache files w/ this
                                           version */
    int num_kt_types;			/* # of registered keytab types */
    struct krb5_keytab_data *kt_types;  /* registered keytab types */
    const char *date_fmt;
    char *error_string;
    krb5_error_code error_code;
    krb5_addresses *ignore_addresses;
    char *default_cc_name;
    char *default_cc_name_env;
    int default_cc_name_set;
    void *mutex;			/* protects error_string */
    int large_msg_size;
    int max_msg_size;
    unsigned max_srv_entries;
    krb5_deltat tgs_negative_timeout;		/* timeout for TGS negative cache */
    int flags;
#define KRB5_CTX_F_DNS_CANONICALIZE_HOSTNAME	1
#define KRB5_CTX_F_CHECK_PAC			2
#define KRB5_CTX_F_HOMEDIR_ACCESS		4
#define KRB5_CTX_F_SOCKETS_INITIALIZED          8
#define KRB5_CTX_F_RD_REQ_IGNORE		16
    struct send_to_kdc *send_to_kdc;
#ifdef PKINIT
    hx509_context hx509ctx;
#endif
    unsigned int num_kdc_requests;
} krb5_context_data;

#ifndef KRB5_USE_PATH_TOKENS
#define KRB5_DEFAULT_CCNAME_FILE "FILE:/tmp/krb5cc_%{uid}"
#else
#define KRB5_DEFAULT_CCNAME_FILE "FILE:%{TEMP}/krb5cc_%{uid}"
#endif
#define KRB5_DEFAULT_CCNAME_API "API:"
#define KRB5_DEFAULT_CCNAME_KCM_KCM "KCM:%{uid}-%{asid}"
#define KRB5_DEFAULT_CCNAME_KCM_API "API:%{uid}-%{asid}"

#define EXTRACT_TICKET_ALLOW_CNAME_MISMATCH		1
#define EXTRACT_TICKET_ALLOW_SERVER_MISMATCH		2
#define EXTRACT_TICKET_MATCH_REALM			4
#define EXTRACT_TICKET_AS_REQ				8
#define EXTRACT_TICKET_TIMESYNC				16
#define EXTRACT_TICKET_REQUIRE_ENC_PA			32

/*
 * Configurable options
 */

#ifndef KRB5_DEFAULT_CCTYPE
#define KRB5_DEFAULT_CCTYPE (&krb5_fcc_ops)
#endif

#ifndef KRB5_ADDRESSLESS_DEFAULT
#define KRB5_ADDRESSLESS_DEFAULT TRUE
#endif

#ifndef KRB5_FORWARDABLE_DEFAULT
#define KRB5_FORWARDABLE_DEFAULT TRUE
#endif

#ifndef KRB5_DNS_DOMAIN_REALM_DEFAULT
#define KRB5_DNS_DOMAIN_REALM_DEFAULT TRUE
#endif

#ifndef KRB5_CONFIGURATION_CHANGE_NOTIFY_NAME
#define KRB5_CONFIGURATION_CHANGE_NOTIFY_NAME "org.h5l.Kerberos.configuration-changed"
#endif

#ifndef KRB5_FALLBACK_DEFAULT
#define KRB5_FALLBACK_DEFAULT TRUE
#endif

#ifdef PKINIT

struct krb5_pk_identity {
    hx509_verify_ctx verify_ctx;
    hx509_certs certs;
    hx509_cert cert;
    hx509_certs anchors;
    hx509_certs certpool;
    hx509_revoke_ctx revokectx;
    int flags;
#define PKINIT_BTMM 1
};

enum krb5_pk_type {
    PKINIT_WIN2K = 1,
    PKINIT_27 = 2
};

#endif /* PKINIT */

struct _krb5_srv_query_ctx;


struct srv_reply {
    struct heim_base_uniq base;
    uint16_t port;
    uint16_t priority;
    int32_t weight;
    struct _krb5_srv_query_ctx *query;
    heim_sema_t hostsema;
    DNSServiceRef srv_sd;
    DNSServiceRef query_sd;
    heim_queue_t addrinfo_queue;
    char *hostname;
    krb5_krbhst_info *hostinfo;
    struct {
	unsigned int getAddrDone:1;
	unsigned int canceled:1;
	unsigned int recvIPv4:1;
	unsigned int recvIPv6:1;
	unsigned int noIPv4:1;
	unsigned int noIPv6:1;
    } flags;
};

struct _krb5_srv_query_ctx {
    struct heim_base_uniq base;
    krb5_context context;
    heim_sema_t sema;
    struct krb5_krbhst_data *handle;
    char *domain;
    int def_port;
    int proto_num;
    const char *path;

#ifdef __APPLE__
    struct {
	unsigned srvQueryDone:1;
    } state;
    int port;

    /* replys */
    struct srv_reply **array;
    unsigned len;
#endif
};

struct krb5_fast_state {
    enum PA_FX_FAST_REQUEST_enum type;
    unsigned int flags;
#define KRB5_FAST_REPLY_KEY_USE_TO_ENCRYPT_THE_REPLY	0x0001
#define KRB5_FAST_REPLY_KEY_USE_IN_TRANSACTION		0x0002
#define KRB5_FAST_KDC_REPLY_KEY_REPLACED		0x0004
#define KRB5_FAST_REPLY_REPLY_VERIFED			0x0008
#define KRB5_FAST_STRONG				0x0010
#define KRB5_FAST_EXPECTED				0x0020 /* in exchange with KDC, fast was discovered */
#define KRB5_FAST_REQUIRED				0x0040 /* fast required by action of caller */
#define KRB5_FAST_DISABLED				0x0080

#define KRB5_FAST_AP_ARMOR_SERVICE			0x0100
#define KRB5_FAST_OPTIMISTIC				0x0200  /* Optimistic try, like Anon + PKINIT or service fast bit */
#define KRB5_FAST_REQUIRE_ENC_PA			0x0400

#define KRB5_FAST_AS_REQ				0x1000


    krb5_keyblock *reply_key;
    krb5_ccache armor_ccache;
    krb5_auth_context armor_ac;
    KrbFastArmor *armor_data;
    krb5_principal armor_service;
    krb5_crypto armor_crypto;
    krb5_keyblock armor_key;
    krb5_keyblock *strengthen_key;
};

struct krb5_decrypt_tkt_with_subkey_state {
    krb5_keyblock *subkey;
    struct krb5_fast_state *fast_state;
};

#endif /* __KRB5_LOCL_H__ */
