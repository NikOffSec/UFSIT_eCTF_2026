#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* Platform / build shape */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_DEV_RANDOM
#define NO_WRITEV
#define WC_NO_DEFAULT_DEVID
#define WOLFSSL_NO_SOCK

/* We are using wolfCrypt only, not TLS */
#define WOLFCRYPT_ONLY
#define NO_OLD_TLS

/* Keep memory / stdlib assumptions simple */
#define WOLFSSL_NO_STDIO
#define WOLFSSL_NO_ERROR_STRINGS

/* AES-GCM/GMAC support */
#define HAVE_AESGCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AESGCM

/* ECC Support */
#define HAVE_ED25519
#define HAVE_ED25519_VERIFY
#define HAVE_ED25519_SIGN
#define HAVE_ED25519_KEY_IMPORT
#define CUSTOM_RAND_GENERATE_BLOCK

#define WOLFSSL_NO_MALLOC 
#define WC_NO_CONSTRUCTORS
#define WOLFSSL_SHA512
#define WOLFSSL_SHA256

/* Disable algorithms you don't need */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_DES3
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_SHA256
#define NO_SHA512
#define NO_HMAC
#define NO_PWDBASED
#define NO_ASN
#define NO_CERTS
#define NO_SESSION_CACHE
#define NO_CODING

/* Important: avoid random/DRBG dependencies for this build */
#define WC_NO_RNG

#endif /* WOLFSSL_USER_SETTINGS_H */
