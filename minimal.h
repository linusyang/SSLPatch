/*
 *    SSLPatch (CVE-2014-1266)
 *    https://github.com/linusyang/SSLPatch
 *
 *    Runtime Patch for SSL verfication exploit (CVE-2014-1266)
 *    Copyright (c) 2014 Linus Yang <laokongzi@gmail.com>
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * Copyright (c) 1999-2001,2005-2012 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <Security/Security.h>
#include <Security/SecureTransport.h>

#undef USE_CDSA_CRYPTO              /* use corecrypto, instead of CDSA */
#undef USE_SSLCERTIFICATE           /* use CF-based certs, not structs */
#define ENABLE_SSLV2                0
#define ENABLE_DTLS                 1
#define SSL_CLIENT_SRVR_RAND_SIZE       32
#define SSL_ECDSA_NUM_CURVES    3
#define SSL_MASTER_SECRET_SIZE          48
#define SSL_MD5_DIGEST_LEN      16
#define SSL_SHA1_DIGEST_LEN     20
#define SSL_MAX_DIGEST_LEN      48 /* >= SSL_MD5_DIGEST_LEN + SSL_SHA1_DIGEST_LEN */
#define APPLE_DH        1
#define SSL_PAC_SERVER_ENABLE       0
#define sslErrorLog(args...)
#define sslEcdsaDebug(args...)
#define dumpBuf(n, b)
#define check(x)

typedef struct __CFRuntimeBase {
    uintptr_t _cfisa;
    uint8_t _cfinfo[4];
#if __LP64__
    uint32_t _rc;
#endif
} CFRuntimeBase;

typedef struct
{   SSLReadFunc         read;
    SSLWriteFunc        write;
    SSLConnectionRef    ioRef;
} IOContext;

/* Opaque reference to a Record Context */
typedef void * SSLRecordContextRef;

typedef enum
{
    /* This value never appears in the actual protocol */
    SSL_Version_Undetermined = 0,
    /* actual protocol values */
    SSL_Version_2_0 = 0x0002,
    SSL_Version_3_0 = 0x0300,
    TLS_Version_1_0 = 0x0301,       /* TLS 1.0 == SSL 3.1 */
    TLS_Version_1_1 = 0x0302,
    TLS_Version_1_2 = 0x0303,
    DTLS_Version_1_0 = 0xfeff,
} SSLProtocolVersion;


#if TARGET_OS_IPHONE
typedef struct __SecKey SSLPubKey;
typedef struct __SecKey SSLPrivKey;
#else
typedef struct OpaqueSecKeyRef SSLPubKey;
typedef struct OpaqueSecKeyRef SSLPrivKey;
#endif

typedef struct OpaqueSecDHContext *SecDHContext;

/*
 * This is the buffer type used internally.
 */
typedef struct
{   size_t  length;
    uint8_t *data;
} SSLBuffer;

/*
 * These are the named curves from RFC 4492
 * section 5.1.1, with the exception of SSL_Curve_None which means
 * "ECDSA not negotiated".
 */
typedef enum
{
    SSL_Curve_None = -1,

    SSL_Curve_sect163k1 = 1,
    SSL_Curve_sect163r1 = 2,
    SSL_Curve_sect163r2 = 3,
    SSL_Curve_sect193r1 = 4,
    SSL_Curve_sect193r2 = 5,
    SSL_Curve_sect233k1 = 6,
    SSL_Curve_sect233r1 = 7,
    SSL_Curve_sect239k1 = 8,
    SSL_Curve_sect283k1 = 9,
    SSL_Curve_sect283r1 = 10,
    SSL_Curve_sect409k1 = 11,
    SSL_Curve_sect409r1 = 12,
    SSL_Curve_sect571k1 = 13,
    SSL_Curve_sect571r1 = 14,
    SSL_Curve_secp160k1 = 15,
    SSL_Curve_secp160r1 = 16,
    SSL_Curve_secp160r2 = 17,
    SSL_Curve_secp192k1 = 18,
    SSL_Curve_secp192r1 = 19,
    SSL_Curve_secp224k1 = 20,
    SSL_Curve_secp224r1 = 21,
    SSL_Curve_secp256k1 = 22,

    /* These are the ones we actually support */
    SSL_Curve_secp256r1 = 23,
    SSL_Curve_secp384r1 = 24,
    SSL_Curve_secp521r1 = 25
} SSL_ECDSA_NamedCurve;

typedef enum
{   SSL_HdskHelloRequest = 0,
    SSL_HdskClientHello = 1,
    SSL_HdskServerHello = 2,
#if ENABLE_DTLS
    SSL_HdskHelloVerifyRequest = 3,
#endif /* ENABLE_DTLS */
    SSL_HdskCert = 11,
    SSL_HdskServerKeyExchange = 12,
    SSL_HdskCertRequest = 13,
    SSL_HdskServerHelloDone = 14,
    SSL_HdskCertVerify = 15,
    SSL_HdskClientKeyExchange = 16,
    SSL_HdskFinished = 20
} SSLHandshakeType;

typedef struct
{   SSLHandshakeType    type;
    SSLBuffer           contents;
} SSLHandshakeMsg;

typedef enum
{   SSL_NULL_auth,
    SSL_RSA,
    SSL_RSA_EXPORT,
    SSL_DH_DSS,
    SSL_DH_DSS_EXPORT,
    SSL_DH_RSA,
    SSL_DH_RSA_EXPORT,
    SSL_DHE_DSS,
    SSL_DHE_DSS_EXPORT,
    SSL_DHE_RSA,
    SSL_DHE_RSA_EXPORT,
    SSL_DH_anon,
    SSL_DH_anon_EXPORT,
    SSL_Fortezza,

    /* ECDSA addenda, RFC 4492 */
    SSL_ECDH_ECDSA,
    SSL_ECDHE_ECDSA,
    SSL_ECDH_RSA,
    SSL_ECDHE_RSA,
    SSL_ECDH_anon,

    /* PSK, RFC 4279 */
    TLS_PSK,
    TLS_DHE_PSK,
    TLS_RSA_PSK,
    
} KeyExchangeMethod;

/* The HMAC algorithms we support */
typedef enum {
    HA_Null = 0,        // i.e., uninitialized
    HA_SHA1,
    HA_MD5,
    HA_SHA256,
    HA_SHA384
} HMAC_Algs;

typedef struct {
    SSLCipherSuite                    cipherSpec;
    KeyExchangeMethod                 keyExchangeMethod;
    uint8_t                           keySize;  /* size in bytes */
    uint8_t                           ivSize;
    uint8_t                           blockSize;
    uint8_t                           macSize;
    HMAC_Algs                         macAlg;
} SSLCipherSpecParams;

typedef enum
{
    SSL_HdskStateUninit = 0,            /* only valid within SSLContextAlloc */
    SSL_HdskStateServerUninit,          /* no handshake yet */
    SSL_HdskStateClientUninit,          /* no handshake yet */
    SSL_HdskStateGracefulClose,
    SSL_HdskStateErrorClose,
    SSL_HdskStateNoNotifyClose,         /* server disconnected with no
                                         *   notify msg */
    /* remainder must be consecutive */
    SSL_HdskStateServerHello,           /* must get server hello; client hello sent */
    SSL_HdskStateKeyExchange,           /* must get key exchange; cipher spec
                                         *   requires it */
    SSL_HdskStateCert,                  /* may get certificate or certificate
                                         *   request (if no cert request received yet) */
    SSL_HdskStateHelloDone,             /* must get server hello done; after key
                                         *   exchange or fixed DH parameters */
    SSL_HdskStateClientCert,            /* must get certificate or no cert alert
                                         *   from client */
    SSL_HdskStateClientKeyExchange,     /* must get client key exchange */
    SSL_HdskStateClientCertVerify,      /* must get certificate verify from client */
    SSL_HdskStateChangeCipherSpec,      /* time to change the cipher spec */
    SSL_HdskStateFinished,              /* must get a finished message in the
                                         *   new cipher spec */
    SSL_HdskStateServerReady,          /* ready for I/O; server side */
    SSL_HdskStateClientReady           /* ready for I/O; client side */
} SSLHandshakeState;

typedef struct DNListElem
{   struct DNListElem   *next;
    SSLBuffer           derDN;
} DNListElem;

typedef struct
{
    uint8_t                 contentType;
    SSLProtocolVersion      protocolVersion;
    SSLBuffer               contents;
} SSLRecord;

typedef struct WaitingMessage
{
    struct WaitingMessage *next;
    SSLRecord   rec;
} WaitingMessage;

/*
 * Callback function for EAP-style PAC-based session resumption.
 * This function is called by SecureTransport to obtain the
 * master secret.
 */
typedef void (*SSLInternalMasterSecretFunction)(
    SSLContextRef ctx,
    const void *arg,        /* opaque to SecureTransport; app-specific */
    void *secret,           /* mallocd by caller, SSL_MASTER_SECRET_SIZE */
    size_t *secretLength);  /* in/out */

/*
 * Server-specified client authentication mechanisms.
 */
typedef enum {
    /* doesn't appear on the wire */
    SSLClientAuthNone = -1,
    /* RFC 2246 7.4.6 */
    SSLClientAuth_RSASign = 1,
    SSLClientAuth_DSSSign = 2,
    SSLClientAuth_RSAFixedDH = 3,
    SSLClientAuth_DSS_FixedDH = 4,
    /* RFC 4492 5.5 */
    SSLClientAuth_ECDSASign = 64,
    SSLClientAuth_RSAFixedECDH = 65,
    SSLClientAuth_ECDSAFixedECDH = 66
} SSLClientAuthenticationType;

/* TLS 1.2 Signature Algorithms extension values for hash field. */
typedef enum {
    SSL_HashAlgorithmNone = 0,
    SSL_HashAlgorithmMD5 = 1,
    SSL_HashAlgorithmSHA1 = 2,
    SSL_HashAlgorithmSHA224 = 3,
    SSL_HashAlgorithmSHA256 = 4,
    SSL_HashAlgorithmSHA384 = 5,
    SSL_HashAlgorithmSHA512 = 6
} SSL_HashAlgorithm;

/* TLS 1.2 Signature Algorithms extension values for signature field. */
typedef enum {
    SSL_SignatureAlgorithmAnonymous = 0,
    SSL_SignatureAlgorithmRSA = 1,
    SSL_SignatureAlgorithmDSA = 2,
    SSL_SignatureAlgorithmECDSA = 3
} SSL_SignatureAlgorithm;

typedef struct {
    SSL_HashAlgorithm hash;
    SSL_SignatureAlgorithm signature;
} SSLSignatureAndHashAlgorithm;

/* CurveTypes in a Server Key Exchange msg */
typedef enum
{
    SSL_CurveTypeExplicitPrime = 1,
    SSL_CurveTypeExplicitChar2 = 2,
    SSL_CurveTypeNamed         = 3      /* the only one we support */
} SSL_ECDSA_CurveTypes;

struct SSLContext
{
    CFRuntimeBase       _base;
    IOContext           ioCtx;

    const struct SSLRecordFuncs *recFuncs;
    SSLRecordContextRef recCtx;
    
    /* 
     * Prior to successful protocol negotiation, negProtocolVersion
     * is SSL_Version_Undetermined. Subsequent to successful
     * negotiation, negProtocolVersion contains the actual over-the-wire
     * protocol value.
     *
     * The Boolean versionEnable flags are set by
     * SSLSetProtocolVersionEnabled or SSLSetProtocolVersion and
     * remain invariant once negotiation has started. If there
     * were a large number of these and/or we were adding new
     * protocol versions on a regular basis, we'd probably want
     * to implement these as a word of flags. For now, in the
     * real world, this is the most straightforward implementation.
     */
    SSLProtocolVersion  negProtocolVersion; /* negotiated */
    SSLProtocolVersion  clientReqProtocol;  /* requested by client in hello msg */
    SSLProtocolVersion  minProtocolVersion;
    SSLProtocolVersion  maxProtocolVersion;
    Boolean             isDTLS;             /* if this is a Datagram Context */
    SSLProtocolSide     protocolSide;       /* ConnectionEnd enum { server, client } in rfc5246. */

    const struct _SslTlsCallouts *sslTslCalls; /* selects between SSLv3, TLSv1 and TLSv1.2 */

    SSLPrivKey          *signingPrivKeyRef;  /* our private signing key */
    SSLPubKey           *signingPubKey;      /* our public signing key */

    SSLPrivKey          *encryptPrivKeyRef;  /* our private encrypt key, for
                                              * server-initiated key exchange */
    SSLPubKey           *encryptPubKey;      /* public version of above */

    SSLPubKey           *peerPubKey;

#ifdef USE_SSLCERTIFICATE
    /*
     * Various cert chains.
     * For all three, the root is the first in the chain.
     */
    SSLCertificate      *localCert;
    SSLCertificate      *encryptCert;
    SSLCertificate      *peerCert;
    CSSM_ALGORITHMS     ourSignerAlg;   /* algorithm of the signer of localCert */
#else
    /*
     * Various cert chains.
     * For all three, the root is the last in the chain.
     */
    CFArrayRef          localCert;
    CFArrayRef          encryptCert;
    CFArrayRef          peerCert;
    CFIndex          ourSignerAlg;  /* algorithm of the signer of localCert */
#endif /* !USE_SSLCERTIFICATE */

    /*
     * The arrays we are given via SSLSetCertificate() and SSLSetEncryptionCertificate().
     * We keep them here, refcounted, solely for the associated getters.
     */
    CFArrayRef          localCertArray;
    CFArrayRef          encryptCertArray;

    /* peer certs as SecTrustRef */
    SecTrustRef         peerSecTrust;

#ifdef USE_CDSA_CRYPTO

    /*
     * trusted root certs as specified in SSLSetTrustedRoots()
     */
    CFArrayRef          trustedCerts;

    /* for symmetric cipher and RNG */
    CSSM_CSP_HANDLE     cspHand;

    /* session-wide handles for Apple TP, CL */
    CSSM_TP_HANDLE      tpHand;
    CSSM_CL_HANDLE      clHand;
#else

#ifdef USE_SSLCERTIFICATE
    size_t              numTrustedCerts;
    SSLCertificate      *trustedCerts;
#else
    CFMutableArrayRef   trustedCerts;
    Boolean             trustedCertsOnly;
#endif /* !USE_SSLCERTIFICATE */

#endif /* !USE_CDSA_CRYPTO */

    /*
     * trusted leaf certs as specified in SSLSetTrustedLeafCertificates()
     */
    CFArrayRef          trustedLeafCerts;

    #if     APPLE_DH
    SSLBuffer           dhPeerPublic;
    SSLBuffer           dhExchangePublic;
    SSLBuffer           dhParamsEncoded;    /* PKCS3 encoded blob - prime + generator */
#ifdef USE_CDSA_CRYPTO
    CSSM_KEY_PTR        dhPrivate;
#else
    SecDHContext        secDHContext;
#endif /* !USE_CDSA_CRYPTO */
    #endif  /* APPLE_DH */

    /*
     * ECDH support
     *
     * ecdhCurves[] is the set of currently configured curves; the number
     * of valid curves is ecdhNumCurves.
     */
    SSL_ECDSA_NamedCurve    ecdhCurves[SSL_ECDSA_NUM_CURVES];
    unsigned                ecdhNumCurves;

    SSLBuffer               ecdhPeerPublic;     /* peer's public ECDH key as ECPoint */
    SSL_ECDSA_NamedCurve    ecdhPeerCurve;      /* named curve associated with ecdhPeerPublic or
                                                 *    peerPubKey */
    SSLBuffer               ecdhExchangePublic; /* Our public key as ECPoint */
#ifdef USE_CDSA_CRYPTO
    CSSM_KEY_PTR            ecdhPrivate;        /* our private key */
    CSSM_CSP_HANDLE         ecdhPrivCspHand;
#else
    // ccec_full_ctx_decl(ccn_sizeof(521), ecdhContext);   // Big enough to hold a 521 bit ecdh key pair.
    // Hack to fill the padding of above ccec_full_ctx_decl
    long ecdhContext__padding_x;
    long ecdhContext__padding_y;
    char ecdhContext[292];
#endif /* !USE_CDSA_CRYPTO */

    Boolean                 allowExpiredCerts;
    Boolean                 allowExpiredRoots;
    Boolean                 enableCertVerify;

    SSLBuffer           dtlsCookie;             /* DTLS ClientHello cookie */
    Boolean             cookieVerified;         /* Mark if cookie was verified */
    uint16_t            hdskMessageSeq;         /* Handshake Seq Num to be sent */
    uint32_t            hdskMessageRetryCount;  /* retry cont for a given flight of messages */
    uint16_t            hdskMessageSeqNext;     /* Handshake Seq Num to be received */
    SSLHandshakeMsg     hdskMessageCurrent;     /* Current Handshake Message */
    uint16_t            hdskMessageCurrentOfs;  /* Offset in current Handshake Message */

    SSLBuffer           sessionID;

    SSLBuffer           peerID;
    SSLBuffer           resumableSession;

    char                *peerDomainName;
    size_t              peerDomainNameLen;
    
    uint8_t             readCipher_ready;
    uint8_t             writeCipher_ready;
    uint8_t             readPending_ready;
    uint8_t             writePending_ready;
    uint8_t             prevCipher_ready;             /* previous write cipher context, used for retransmit */
    
    uint16_t            selectedCipher;         /* currently selected */
    SSLCipherSpecParams selectedCipherSpecParams;     /* ditto */

    SSLCipherSuite      *validCipherSuites;     /* context's valid suites */
    size_t              numValidCipherSuites;   /* size of validCipherSuites */
#if ENABLE_SSLV2
    unsigned            numValidNonSSLv2Suites; /* number of entries in validCipherSpecs that
                                                 * are *not* SSLv2 only */
#endif
    SSLHandshakeState   state;

    /* server-side only */
    SSLAuthenticate     clientAuth;             /* kNeverAuthenticate, etc. */
    Boolean             tryClientAuth;

    /* client and server */
    SSLClientCertificateState   clientCertState;

    DNListElem          *acceptableDNList;      /* client and server */
    CFMutableArrayRef   acceptableCAs;          /* server only - SecCertificateRefs */

    bool                certRequested;
    bool                certSent;
    bool                certReceived;
    bool                x509Requested;

    uint8_t             clientRandom[SSL_CLIENT_SRVR_RAND_SIZE];
    uint8_t             serverRandom[SSL_CLIENT_SRVR_RAND_SIZE];
    SSLBuffer           preMasterSecret;
    uint8_t             masterSecret[SSL_MASTER_SECRET_SIZE];

    /* running digests of all handshake messages */
    SSLBuffer           shaState, md5State, sha256State, sha512State;

    SSLBuffer           fragmentedMessageCache;

    unsigned            ssl2ChallengeLength;
    unsigned            ssl2ConnectionIDLength;
    unsigned            sessionMatch;

    /* Queue a full flight of messages */
    WaitingMessage      *messageWriteQueue;
    Boolean             messageQueueContainsChangeCipherSpec;
    
    /* Transport layer fields */
    SSLBuffer           receivedDataBuffer;
    size_t              receivedDataPos;

    Boolean             allowAnyRoot;       // don't require known roots
    Boolean             sentFatalAlert;     // this session terminated by fatal alert
    Boolean             rsaBlindingEnable;
    Boolean             oneByteRecordEnable;    /* enable 1/n-1 data splitting for TLSv1 and SSLv3 */
    Boolean             wroteAppData;           /* at least one write completed with current writeCipher */

    /* optional session cache timeout (in seconds) override - 0 means default */
    uint32_t                sessionCacheTimeout;

    /* optional SessionTicket */
    SSLBuffer           sessionTicket;

    /* optional callback to obtain master secret, with its opaque arg */
    SSLInternalMasterSecretFunction masterSecretCallback;
    const void          *masterSecretArg;

    #if     SSL_PAC_SERVER_ENABLE
    /* server PAC resume sets serverRandom early to allow for secret acquisition */
    uint8_t             serverRandomValid;
    #endif

    Boolean             anonCipherEnable;

    /* optional switches to enable additional returns from SSLHandshake */
    Boolean             breakOnServerAuth;
    Boolean             breakOnCertRequest;
    Boolean             breakOnClientAuth;
    Boolean             signalServerAuth;
    Boolean             signalCertRequest;
    Boolean             signalClientAuth;

    /* true iff ECDSA/ECDH ciphers are configured */
    Boolean             ecdsaEnable;

    /* List of server-specified client auth types */
    unsigned                    numAuthTypes;
    SSLClientAuthenticationType *clientAuthTypes;

    /* client auth type actually negotiated */
    SSLClientAuthenticationType negAuthType;

    /* List of client-specified supported_signature_algorithms (for key exchange) */
    unsigned                     numClientSigAlgs;
    SSLSignatureAndHashAlgorithm *clientSigAlgs;
    /* List of server-specified supported_signature_algorithms (for client cert) */
    unsigned                     numServerSigAlgs;
    SSLSignatureAndHashAlgorithm *serverSigAlgs;


    /* Timeout for DTLS retransmit */
    CFAbsoluteTime      timeout_deadline;
    CFAbsoluteTime      timeout_duration;
    size_t              mtu;

    /* RFC 5746: Secure renegotiation */
    Boolean             secure_renegotiation;
    Boolean             secure_renegotiation_received;
    SSLBuffer           ownVerifyData;
    SSLBuffer           peerVerifyData;

    /* RFC 4279: TLS PSK */
    SSLBuffer           pskSharedSecret;
    SSLBuffer           pskIdentity;

    /* TLS False Start */
    Boolean             falseStartEnabled; //FalseStart enabled (by API call)
};

typedef struct SSLContext SSLContext;

typedef int (*HashInit)(SSLBuffer *digestCtx);
typedef int (*HashUpdate)(SSLBuffer *digestCtx, const SSLBuffer *data);
/* HashFinal also does HashClose */
typedef int (*HashFinal)(SSLBuffer *digestCtx, SSLBuffer *digest);
typedef int (*HashClose)(SSLBuffer *digestCtx);
typedef int (*HashClone)(const SSLBuffer *src, SSLBuffer *dest);

typedef struct
{
    uint32_t    digestSize;
    uint32_t    macPadSize;
    uint32_t    contextSize;
    HashInit    init;
    HashUpdate  update;
    HashFinal   final;
    HashClose   close;
    HashClone   clone;
} HashReference;

#if TARGET_OS_IPHONE
typedef struct {
    size_t Length;
    uint8_t *Data;
} SecAsn1Item, SecAsn1Oid;

typedef struct {
    SecAsn1Oid algorithm;
    SecAsn1Item parameters;
} SecAsn1AlgId;
#endif

// External symbols
const SecAsn1Oid *_CSSMOID_SHA1WithRSA;
const SecAsn1Oid *_CSSMOID_SHA256WithRSA;
const SecAsn1Oid *_CSSMOID_SHA384WithRSA;

const HashReference *_SSLHashMD5;
const HashReference *_SSLHashSHA1;
const HashReference *_SSLHashSHA256;
const HashReference *_SSLHashSHA384;

int (*_SSLAllocBuffer)(SSLBuffer *buf, size_t length);
int (*_SSLFreeBuffer)(SSLBuffer *buf);
uint32_t (*_SSLDecodeInt)(
    const uint8_t *     p,
    size_t              length);
OSStatus (*_sslFreePubKey)(SSLPubKey **pubKey);
OSStatus (*_sslGetPubKeyFromBits)(
    SSLContext          *ctx,
    const SSLBuffer     *modulus,
    const SSLBuffer     *exponent,
    SSLPubKey           **pubKey);
OSStatus (*_ReadyHash)(
    const HashReference *ref, 
    SSLBuffer *state);
OSStatus (*_SSLDecodeDHKeyParams)(SSLContext *ctx, uint8_t **charPtr,
    size_t length);
OSStatus (*_sslRsaVerify)(
    SSLContext          *ctx,
    SSLPubKey           *pubKey,
    const SecAsn1AlgId  *algId,
    const uint8_t       *plainText,
    size_t              plainTextLen,
    const uint8_t       *sig,
    size_t              sigLen);
OSStatus (*_sslRawVerify)(
    SSLContext          *ctx,
    SSLPubKey           *pubKey,
    const uint8_t       *plainText,
    size_t              plainTextLen,
    const uint8_t       *sig,
    size_t              sigLen);

// API
#ifdef __cplusplus
extern "C" {
#endif

OSStatus custom_SSLProcessServerKeyExchange(SSLBuffer message, SSLContext *ctx);

#ifdef __cplusplus
}
#endif
