
#define HDB_DB_DIR "/var/db/krb5kdc"

#define __APPLE_PRIVATE__ 1
#define __GSS_ITER_CRED_USES_CONST_OID 1

#define __APPLE_USE_RFC_3542 1

#define HEIMDAL_SMALLER 1
#define NO_NTLM 1
#define NO_AFS 1
#define KCM_IS_API_CACHE 1
#define KRB5_DNS_DOMAIN_REALM_DEFAULT 0
#define NO_RAND_FORTUNA_METHOD 1
#define NO_RAND_UNIX_METHOD 1
#define NO_RAND_EGD_METHOD 1

#define HAVE_COMMONCRYPTO_COMMONKEYDERIVATION_H 1
#define HAVE_COMMONCRYPTO_COMMONCRYPTOR_H 1

#define KRB5_FALLBACK_DEFAULT FALSE

/* key derivation */
/* keychain */
/* IP_RECVPKTINFO */
#define HAVE_NOTIFY_H 1
#define KRB5_CONFIGURATION_CHANGE_NOTIFY_NAME "com.apple.Kerberos.configuration-changed"

#define DEFAULT_KDC_LOG_DEST "SYSLOG:AUTHPRIV:NOTICE"

#ifdef __APPLE_TARGET_EMBEDDED__

#define HEIM_KRB5_DES3 1
#define HEIM_KRB5_ARCFOUR 1

#define HAVE_KCC /* disabled for desktop until rdar://8742062 is fixed */
#define KRB5_DEFAULT_CCTYPE (&krb5_kcc_ops)

#define HEIM_HC_LTM 1
#define HEIM_HC_SF 1

#undef PKINIT

#define HAVE_CCDESISWEAKKEY 1
#define HAVE_CCDIGESTCREATE 1

#else

#ifndef PKINIT
#define PKINIT 1
#endif

#define HAVE_TRUSTEVALUATIONAGENT 1
#define HAVE_OPENDIRECTORY 1
#define HAVE_CDSA 1
#define HAVE_COMMONCRYPTO_COMMONCRYPTORSPI_H 1

#define ENABLE_NTLM 1
#define ENABLE_SCRAM 1

#define HEIM_KRB5_DES 1
#define HEIM_KRB5_DES3 1
#define HEIM_KRB5_ARCFOUR 1

#define HAVE_CCDESISWEAKKEY 1
#define HAVE_CCDIGESTCREATE 1

/* #define HEIM_KT_ANY */
/* #define HEIM_KT_MEMORY */
/* #define HEIM_KT_AKF */

#define KRB5_DEFAULT_CCTYPE (&krb5_akcm_ops)


#endif