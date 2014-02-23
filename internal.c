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

#include "internal.h"
#include <AssertMacros.h>

/*** MD5 ***/
static int HashMD5Init(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_MD5_CTX));
    CC_MD5_CTX *ctx = (CC_MD5_CTX *)digestCtx->data;
    CC_MD5_Init(ctx);
    dgprintf(("###HashMD5Init  ctx %p\n", ctx));
    return 0;
}

static int HashMD5Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    assert(digestCtx->length >= sizeof(CC_MD5_CTX));
    CC_MD5_CTX *ctx = (CC_MD5_CTX *)digestCtx->data;
    CC_MD5_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashMD5Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    assert(digestCtx->length >= sizeof(CC_MD5_CTX));
    CC_MD5_CTX *ctx = (CC_MD5_CTX *)digestCtx->data;
    dgprintf(("###HashMD5Final  ctx %p\n", ctx));
    assert(digest->length >= CC_MD5_DIGEST_LENGTH);
    //if (digest->length < CC_MD5_DIGEST_LENGTH)
    //  return errSSLCrypto;
    CC_MD5_Final(digest->data, ctx);
    digest->length = CC_MD5_DIGEST_LENGTH;
    return 0;
}

static int HashMD5Close(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_MD5_CTX));
    return 0;
}

static int HashMD5Clone(const SSLBuffer *src, SSLBuffer *dst)
{
    CC_MD5_CTX *srcCtx;
    CC_MD5_CTX *dstCtx;

    assert(src->length >= sizeof(CC_MD5_CTX));
    assert(dst->length >= sizeof(CC_MD5_CTX));

    srcCtx = (CC_MD5_CTX *)src->data;
    dstCtx = (CC_MD5_CTX *)dst->data;
    dgprintf(("###HashMD5Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));

    memcpy(dstCtx, srcCtx, sizeof(CC_MD5_CTX));
    return 0;
}

/*** SHA1 ***/
static int HashSHA1Init(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
    CC_SHA1_CTX *ctx = (CC_SHA1_CTX *)digestCtx->data;
    CC_SHA1_Init(ctx);
    dgprintf(("###HashSHA1Init  ctx %p\n", ctx));
    return 0;
}

static int HashSHA1Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
    CC_SHA1_CTX *ctx = (CC_SHA1_CTX *)digestCtx->data;
    CC_SHA1_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashSHA1Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
    CC_SHA1_CTX *ctx = (CC_SHA1_CTX *)digestCtx->data;
    dgprintf(("###HashSHA1Final  ctx %p\n", ctx));
    assert(digest->length >= CC_SHA1_DIGEST_LENGTH);
    //if (digest->length < CC_SHA1_DIGEST_LENGTH)
    //  return errSSLCrypto;
    CC_SHA1_Final(digest->data, ctx);
    digest->length = CC_SHA1_DIGEST_LENGTH;
    return 0;
}

static int HashSHA1Close(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_SHA1_CTX));
    return 0;
}

static int HashSHA1Clone(const SSLBuffer *src, SSLBuffer *dst)
{
    CC_SHA1_CTX *srcCtx;
    CC_SHA1_CTX *dstCtx;

    assert(src->length >= sizeof(CC_SHA1_CTX));
    assert(dst->length >= sizeof(CC_SHA1_CTX));

    srcCtx = (CC_SHA1_CTX *)src->data;
    dstCtx = (CC_SHA1_CTX *)dst->data;
    dgprintf(("###HashSHA1Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));

    memcpy(dstCtx, srcCtx, sizeof(CC_SHA1_CTX));
    return 0;
}

/*** SHA256 ***/
static int HashSHA256Init(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
    CC_SHA256_CTX *ctx = (CC_SHA256_CTX *)digestCtx->data;
    CC_SHA256_Init(ctx);
    dgprintf(("###HashSHA256Init  ctx %p\n", ctx));
    return 0;
}

static int HashSHA256Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
    CC_SHA256_CTX *ctx = (CC_SHA256_CTX *)digestCtx->data;
    CC_SHA256_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashSHA256Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
    CC_SHA256_CTX *ctx = (CC_SHA256_CTX *)digestCtx->data;
    dgprintf(("###HashSHA256Final  ctx %p\n", ctx));
    assert(digest->length >= CC_SHA256_DIGEST_LENGTH);
    //if (digest->length < CC_SHA256_DIGEST_LENGTH)
    //  return errSSLCrypto;
    CC_SHA256_Final(digest->data, ctx);
    digest->length = CC_SHA256_DIGEST_LENGTH;
    return 0;
}

static int HashSHA256Close(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_SHA256_CTX));
    return 0;
}

static int HashSHA256Clone(const SSLBuffer *src, SSLBuffer *dst)
{
    CC_SHA256_CTX *srcCtx;
    CC_SHA256_CTX *dstCtx;

    assert(src->length >= sizeof(CC_SHA256_CTX));
    assert(dst->length >= sizeof(CC_SHA256_CTX));

    srcCtx = (CC_SHA256_CTX *)src->data;
    dstCtx = (CC_SHA256_CTX *)dst->data;
    dgprintf(("###HashSHA256Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));

    memcpy(dstCtx, srcCtx, sizeof(CC_SHA256_CTX));
    return 0;
}

/*** SHA384 ***/
static int HashSHA384Init(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
    CC_SHA512_CTX *ctx = (CC_SHA512_CTX *)digestCtx->data;
    CC_SHA384_Init(ctx);
    dgprintf(("###HashSHA384Init  ctx %p\n", ctx));
    return 0;
}

static int HashSHA384Update(SSLBuffer *digestCtx, const SSLBuffer *data)
{
    /* 64 bits cast: safe, SSL records are always smaller than 2^32 bytes */
    assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
    CC_SHA512_CTX *ctx = (CC_SHA512_CTX *)digestCtx->data;
    CC_SHA384_Update(ctx, data->data, (CC_LONG)data->length);
    return 0;
}

static int HashSHA384Final(SSLBuffer *digestCtx, SSLBuffer *digest)
{
    assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
    CC_SHA512_CTX *ctx = (CC_SHA512_CTX *)digestCtx->data;
    dgprintf(("###HashSHA384Final  ctx %p\n", ctx));
    assert(digest->length >= CC_SHA384_DIGEST_LENGTH);
    //if (digest->length < CC_SHA384_DIGEST_LENGTH)
    //  return errSSLCrypto;
    CC_SHA384_Final(digest->data, ctx);
    digest->length = CC_SHA384_DIGEST_LENGTH;
    return 0;
}

static int HashSHA384Close(SSLBuffer *digestCtx)
{
    assert(digestCtx->length >= sizeof(CC_SHA512_CTX));
    return 0;
}

static int HashSHA384Clone(const SSLBuffer *src, SSLBuffer *dst)
{
    CC_SHA512_CTX *srcCtx;
    CC_SHA512_CTX *dstCtx;

    assert(src->length >= sizeof(CC_SHA512_CTX));
    assert(dst->length >= sizeof(CC_SHA512_CTX));

    srcCtx = (CC_SHA512_CTX *)src->data;
    dstCtx = (CC_SHA512_CTX *)dst->data;
    dgprintf(("###HashSHA384Clone  srcCtx %p  dstCtx %p\n", srcCtx, dstCtx));

    memcpy(dstCtx, srcCtx, sizeof(CC_SHA512_CTX));
    return 0;
}

static const HashReference SSLHashMD5 =
{
    SSL_MD5_DIGEST_LENGTH,
    48,
    SSL_MD5_CONTEXT_SIZE,
    HashMD5Init,
    HashMD5Update,
    HashMD5Final,
    HashMD5Close,
    HashMD5Clone
};

static const HashReference SSLHashSHA1 =
{
    SSL_SHA1_DIGEST_LENGTH,
    40,
    SSL_SHA1_CONTEXT_SIZE,
    HashSHA1Init,
    HashSHA1Update,
    HashSHA1Final,
    HashSHA1Close,
    HashSHA1Clone
};

static const HashReference SSLHashSHA256 =
{
    SSL_SHA256_DIGEST_LENGTH,
    SSL_SHA256_BLOCK_BYTES,
    SSL_SHA256_CONTEXT_SIZE,
    HashSHA256Init,
    HashSHA256Update,
    HashSHA256Final,
    HashSHA256Close,
    HashSHA256Clone
};

static const HashReference SSLHashSHA384 =
{
    SSL_SHA384_DIGEST_LENGTH,
    SSL_SHA384_BLOCK_BYTES,
    SSL_SHA384_CONTEXT_SIZE,
    HashSHA384Init,
    HashSHA384Update,
    HashSHA384Final,
    HashSHA384Close,
    HashSHA384Clone
};

static void *
sslMalloc(size_t length)
{
    return malloc(length);
}

static void
sslFree(void *p)
{   
    if(p != NULL) {
        free(p);
    }
}

static int SSLAllocBuffer(
    SSLBuffer *buf,
    size_t length)
{
    buf->data = (uint8_t *)sslMalloc(length);
    if(buf->data == NULL) {
        sslErrorLog("SSLAllocBuffer: NULL buf!\n");
        check(0);
        buf->length = 0;
        return -1;
    }
    buf->length = length;
    return 0;
}

static unsigned int
SSLDecodeInt(const uint8_t *p, size_t length)
{
    unsigned int val = 0;
    check(length > 0 && length <= 4); //anything else would be an internal error.
    while (length--)
        val = (val << 8) | *p++;
    return val;
}

static int
SSLFreeBuffer(SSLBuffer *buf)
{   
    if(buf == NULL) {
        sslErrorLog("SSLFreeBuffer: NULL buf!\n");
        check(0);
        return -1;
    }
    sslFree(buf->data);
    buf->data = NULL;
    buf->length = 0;
    return 0;
}

static OSStatus sslFreePubKey(SSLPubKey **pubKey)
{
    if (pubKey && *pubKey) {
        CFReleaseNull(SECKEYREF(*pubKey));
    }
    return errSecSuccess;
}

static OSStatus
ReadyHash(const HashReference *ref, SSLBuffer *state)
{   
    OSStatus      err;
    if ((err = SSLAllocBuffer(state, ref->contextSize)))
        return err;
    return ref->init(state);
}

static OSStatus sslRawVerify(
    SSLContext          *ctx,
    SSLPubKey           *pubKey,
    const uint8_t       *plainText,
    size_t              plainTextLen,
    const uint8_t       *sig,
    size_t              sigLen)         // available
{
#if 0
    RSAStatus rsaStatus;

    rsaStatus = RSA_SigVerify(&pubKey->rsaKey,
        RP_PKCS1,
        plainText,
        plainTextLen,
        sig,
        sigLen);

    return rsaStatus ? rsaStatusToSSL(rsaStatus) : errSecSuccess;
#else
    OSStatus status = SecKeyRawVerify(SECKEYREF(pubKey), kSecPaddingPKCS1,
        plainText, plainTextLen, sig, sigLen);

    if (status) {
        sslErrorLog("sslRawVerify: SecKeyRawVerify failed (error %d)\n", (int) status);
    }

    return status;
#endif
}

static size_t DEREncodeDigestInfoPrefix(const SecAsn1Oid *oid,
                                        size_t digestLength, uint8_t *digestInfo, size_t digestInfoLength) {
    size_t algIdLen = oid->Length + 4;
    size_t topLen = algIdLen + digestLength + 4;
    size_t totalLen = topLen + 2;
    
    if (totalLen > digestInfoLength) {
        return 0;
    }
    
    size_t ix = 0;
    digestInfo[ix++] = (SEC_ASN1_SEQUENCE | SEC_ASN1_CONSTRUCTED);
    digestInfo[ix++] = topLen;
    digestInfo[ix++] = (SEC_ASN1_SEQUENCE | SEC_ASN1_CONSTRUCTED);
    digestInfo[ix++] = algIdLen;
    digestInfo[ix++] = SEC_ASN1_OBJECT_ID;
    digestInfo[ix++] = oid->Length;
    memcpy(&digestInfo[ix], oid->Data, oid->Length);
    ix += oid->Length;
    digestInfo[ix++] = SEC_ASN1_NULL;
    digestInfo[ix++] = 0;
    digestInfo[ix++] = SEC_ASN1_OCTET_STRING;
    digestInfo[ix++] = digestLength;
    
    return ix;
}

static OSStatus SecKeyGetDigestInfo(SecKeyRef this, const SecAsn1AlgId *algId,
                                    const uint8_t *data, size_t dataLen, bool digestData,
                                    uint8_t *digestInfo, size_t *digestInfoLen /* IN/OUT */) {
    unsigned char *(*digestFcn)(const void *, CC_LONG, unsigned char *);
    CFIndex keyAlgID = kSecNullAlgorithmID;
    const SecAsn1Oid *digestOid;
    size_t digestLen;
    size_t offset = 0;
    
    /* Since these oids all have the same prefix, use switch. */
    if ((algId->algorithm.Length == CSSMOID_RSA.Length) &&
        !memcmp(algId->algorithm.Data, CSSMOID_RSA.Data,
                algId->algorithm.Length - 1)) {
            keyAlgID = kSecRSAAlgorithmID;
            switch (algId->algorithm.Data[algId->algorithm.Length - 1]) {
#if 0
                case 2: /* oidMD2WithRSA */
                    digestFcn = CC_MD2;
                    digestLen = CC_MD2_DIGEST_LENGTH;
                    digestOid = &CSSMOID_MD2;
                    break;
                case 3: /* oidMD4WithRSA */
                    digestFcn = CC_MD4;
                    digestLen = CC_MD4_DIGEST_LENGTH;
                    digestOid = &CSSMOID_MD4;
                    break;
                case 4: /* oidMD5WithRSA */
                    digestFcn = CC_MD5;
                    digestLen = CC_MD5_DIGEST_LENGTH;
                    digestOid = &CSSMOID_MD5;
                    break;
#endif /* 0 */
                case 5: /* oidSHA1WithRSA */
                    digestFcn = CC_SHA1;
                    digestLen = CC_SHA1_DIGEST_LENGTH;
                    digestOid = &CSSMOID_SHA1;
                    break;
                case 11: /* oidSHA256WithRSA */
                    digestFcn = CC_SHA256;
                    digestLen = CC_SHA256_DIGEST_LENGTH;
                    digestOid = &CSSMOID_SHA256;
                    break;
                case 12: /* oidSHA384WithRSA */
                    /* pkcs1 12 */
                    digestFcn = CC_SHA384;
                    digestLen = CC_SHA384_DIGEST_LENGTH;
                    digestOid = &CSSMOID_SHA384;
                    break;
                case 13: /* oidSHA512WithRSA */
                    digestFcn = CC_SHA512;
                    digestLen = CC_SHA512_DIGEST_LENGTH;
                    digestOid = &CSSMOID_SHA512;
                    break;
                case 14: /* oidSHA224WithRSA */
                    digestFcn = CC_SHA224;
                    digestLen = CC_SHA224_DIGEST_LENGTH;
                    digestOid = &CSSMOID_SHA224;
                    break;
                default:
                    secdebug("key", "unsupported rsa signature algorithm");
                    return errSecUnsupportedAlgorithm;
            }
        } else if ((algId->algorithm.Length == CSSMOID_ECDSA_WithSHA224.Length) &&
                   !memcmp(algId->algorithm.Data, CSSMOID_ECDSA_WithSHA224.Data,
                           algId->algorithm.Length - 1)) {
                       keyAlgID = kSecECDSAAlgorithmID;
                       switch (algId->algorithm.Data[algId->algorithm.Length - 1]) {
                           case 1: /* oidSHA224WithECDSA */
                               digestFcn = CC_SHA224;
                               digestLen = CC_SHA224_DIGEST_LENGTH;
                               break;
                           case 2: /* oidSHA256WithECDSA */
                               digestFcn = CC_SHA256;
                               digestLen = CC_SHA256_DIGEST_LENGTH;
                               break;
                           case 3: /* oidSHA384WithECDSA */
                               /* pkcs1 12 */
                               digestFcn = CC_SHA384;
                               digestLen = CC_SHA384_DIGEST_LENGTH;
                               break;
                           case 4: /* oidSHA512WithECDSA */
                               digestFcn = CC_SHA512;
                               digestLen = CC_SHA512_DIGEST_LENGTH;
                               break;
                           default:
                               secdebug("key", "unsupported ecdsa signature algorithm");
                               return errSecUnsupportedAlgorithm;
                       }
                   } else if (SecAsn1OidCompare(&algId->algorithm, &CSSMOID_ECDSA_WithSHA1)) {
                       keyAlgID = kSecECDSAAlgorithmID;
                       digestFcn = CC_SHA1;
                       digestLen = CC_SHA1_DIGEST_LENGTH;
                   } else if (SecAsn1OidCompare(&algId->algorithm, &CSSMOID_SHA1)) {
                       digestFcn = CC_SHA1;
                       digestLen = CC_SHA1_DIGEST_LENGTH;
                       digestOid = &CSSMOID_SHA1;
                   } else if ((algId->algorithm.Length == CSSMOID_SHA224.Length) &&
                              !memcmp(algId->algorithm.Data, CSSMOID_SHA224.Data, algId->algorithm.Length - 1))
                   {
                       switch (algId->algorithm.Data[algId->algorithm.Length - 1]) {
                           case 4: /* OID_SHA224 */
                               digestFcn = CC_SHA224;
                               digestLen = CC_SHA224_DIGEST_LENGTH;
                               digestOid = &CSSMOID_SHA224;
                               break;
                           case 1: /* OID_SHA256 */
                               digestFcn = CC_SHA256;
                               digestLen = CC_SHA256_DIGEST_LENGTH;
                               digestOid = &CSSMOID_SHA256;
                               break;
                           case 2: /* OID_SHA384 */
                               /* pkcs1 12 */
                               digestFcn = CC_SHA384;
                               digestLen = CC_SHA384_DIGEST_LENGTH;
                               digestOid = &CSSMOID_SHA384;
                               break;
                           case 3: /* OID_SHA512 */
                               digestFcn = CC_SHA512;
                               digestLen = CC_SHA512_DIGEST_LENGTH;
                               digestOid = &CSSMOID_SHA512;
                               break;
                           default:
                               secdebug("key", "unsupported sha-2 signature algorithm");
                               return errSecUnsupportedAlgorithm;
                       }
                   } else if (SecAsn1OidCompare(&algId->algorithm, &CSSMOID_MD5)) {
                       digestFcn = CC_MD5;
                       digestLen = CC_MD5_DIGEST_LENGTH;
                       digestOid = &CSSMOID_MD5;
                   } else {
                       secdebug("key", "unsupported digesting algorithm");
                       return errSecUnsupportedAlgorithm;
                   }
    
    /* check key is appropriate for signature (superfluous for digest only oid) */
    if (keyAlgID == kSecNullAlgorithmID)
        keyAlgID = SecKeyGetAlgorithmID(this);
    else if (keyAlgID != SecKeyGetAlgorithmID(this))
        return errSecUnsupportedAlgorithm;
    
    switch(keyAlgID) {
        case kSecRSAAlgorithmID:
            offset = DEREncodeDigestInfoPrefix(digestOid, digestLen,
                                               digestInfo, *digestInfoLen);
            if (!offset)
                return errSecBufferTooSmall;
            break;
        case kSecDSAAlgorithmID:
            if (digestOid != &CSSMOID_SHA1)
                return errSecUnsupportedAlgorithm;
            break;
        case kSecECDSAAlgorithmID:
            break;
        default:
            secdebug("key", "unsupported signature algorithm");
            return errSecUnsupportedAlgorithm;
    }
    
    if (digestData) {
        if(dataLen>UINT32_MAX) /* Check for overflow with CC_LONG cast */
            return errSecParam;
        digestFcn(data, (CC_LONG)dataLen, &digestInfo[offset]);
        *digestInfoLen = offset + digestLen;
    } else {
        if (dataLen != digestLen)
            return errSecParam;
        memcpy(&digestInfo[offset], data, dataLen);
        *digestInfoLen = offset + dataLen;
    }
    
    return errSecSuccess;
}

static OSStatus SecKeyVerifyDigest(
                            SecKeyRef           this,            /* Private key */
                            const SecAsn1AlgId  *algId,         /* algorithm oid/params */
                            const uint8_t       *digestData,    /* signature over this digest */
                            size_t              digestDataLen,/* length of dataToDigest */
                            const uint8_t       *sig,           /* signature to verify */
                            size_t              sigLen) {       /* length of sig */
    size_t digestInfoLength = DER_MAX_DIGEST_INFO_LEN;
    uint8_t digestInfo[digestInfoLength];
    OSStatus status;
    
    status = SecKeyGetDigestInfo(this, algId, digestData, digestDataLen, false /* data is digest */,
                                 digestInfo, &digestInfoLength);
    if (status)
        return status;
    return SecKeyRawVerify(this, kSecPaddingPKCS1,
                           digestInfo, digestInfoLength, sig, sigLen);
}

static OSStatus sslRsaVerify(
                      SSLContext          *ctx,
                      SSLPubKey           *pubKey,
                      const SecAsn1AlgId  *algId,
                      const uint8_t       *plainText,
                      size_t              plainTextLen,
                      const uint8_t       *sig,
                      size_t              sigLen)         // available
{
    OSStatus status = SecKeyVerifyDigest(SECKEYREF(pubKey), algId,
                           plainText, plainTextLen, sig, sigLen);

    if (status) {
        sslErrorLog("sslRsaVerify: SecKeyVerifyDigest failed (error %d)\n", (int) status);
    }

    return status;
}

static OSStatus
SSLVerifySignedServerKeyExchange(SSLContext *ctx, bool isRsa, SSLBuffer signedParams,
                                 uint8_t *signature, UInt16 signatureLen)
{
    OSStatus        err;
    SSLBuffer       hashOut, hashCtx, clientRandom, serverRandom;
    uint8_t         hashes[SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN];
    SSLBuffer       signedHashes;
    uint8_t         *dataToSign;
    size_t          dataToSignLen;

    signedHashes.data = 0;
    hashCtx.data = 0;

    clientRandom.data = ctx->clientRandom;
    clientRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;
    serverRandom.data = ctx->serverRandom;
    serverRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;


    if(isRsa) {
        /* skip this if signing with DSA */
        dataToSign = hashes;
        dataToSignLen = SSL_SHA1_DIGEST_LEN + SSL_MD5_DIGEST_LEN;
        hashOut.data = hashes;
        hashOut.length = SSL_MD5_DIGEST_LEN;
        
        if ((err = ReadyHash(&SSLHashMD5, &hashCtx)) != 0)
            goto fail;
        if ((err = SSLHashMD5.update(&hashCtx, &clientRandom)) != 0)
            goto fail;
        if ((err = SSLHashMD5.update(&hashCtx, &serverRandom)) != 0)
            goto fail;
        if ((err = SSLHashMD5.update(&hashCtx, &signedParams)) != 0)
            goto fail;
        if ((err = SSLHashMD5.final(&hashCtx, &hashOut)) != 0)
            goto fail;
    }
    else {
        /* DSA, ECDSA - just use the SHA1 hash */
        dataToSign = &hashes[SSL_MD5_DIGEST_LEN];
        dataToSignLen = SSL_SHA1_DIGEST_LEN;
    }

    hashOut.data = hashes + SSL_MD5_DIGEST_LEN;
    hashOut.length = SSL_SHA1_DIGEST_LEN;
    if ((err = SSLFreeBuffer(&hashCtx)) != 0)
        goto fail;

    if ((err = ReadyHash(&SSLHashSHA1, &hashCtx)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &clientRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &serverRandom)) != 0)
        goto fail;
    if ((err = SSLHashSHA1.update(&hashCtx, &signedParams)) != 0)
        goto fail;
/*      goto fail; (Oops, Epic fail!) */
    if ((err = SSLHashSHA1.final(&hashCtx, &hashOut)) != 0)
        goto fail;

    err = sslRawVerify(ctx,
                       ctx->peerPubKey,
                       dataToSign,              /* plaintext */
                       dataToSignLen,           /* plaintext length */
                       signature,
                       signatureLen);
    if(err) {
        sslErrorLog("SSLDecodeSignedServerKeyExchange: sslRawVerify "
                    "returned %d\n", (int)err);
        goto fail;
    }

fail:
    SSLFreeBuffer(&signedHashes);
    SSLFreeBuffer(&hashCtx);
    return err;

}

static inline bool sslVersionIsLikeTls12(SSLContext *ctx)
{
    check(ctx->negProtocolVersion!=SSL_Version_Undetermined);
    return ctx->isDTLS ? ctx->negProtocolVersion > DTLS_Version_1_0 : ctx->negProtocolVersion >= TLS_Version_1_2;
}

/*
 * Given raw RSA key bits, cook up a SSLPubKey. Used in
 * Server-initiated key exchange.
 */
OSStatus sslGetPubKeyFromBits(
    SSLContext          *ctx,
    const SSLBuffer     *modulus,
    const SSLBuffer     *exponent,
    SSLPubKey           **pubKey)        // mallocd and RETURNED
{
    if (!pubKey)
        return errSecParam;
#if 0
    SSLPubKey *key;
    RSAStatus rsaStatus;
    RSAPubKey apiKey = {
        modulus->data, modulus->length,
        NULL, 0,
        exponent->data, exponent->length
    };

    key = sslMalloc(sizeof(*key));
    rsaStatus = rsaInitPubGKey(&apiKey, &key->rsaKey);
    if (rsaStatus) {
        sslFree(key);
        return rsaStatusToSSL(rsaStatus);
    }

    *pubKey = key;
    return errSecSuccess;
#else
    check(pubKey);
    SecRSAPublicKeyParams params = {
        modulus->data, modulus->length,
        exponent->data, exponent->length
    };
#if SSL_DEBUG
    sslDebugLog("Creating RSA pub key from modulus=%p len=%lu exponent=%p len=%lu\n",
            modulus->data, modulus->length,
            exponent->data, exponent->length);
#endif
    SecKeyRef key = SecKeyCreateRSAPublicKey(NULL, (const uint8_t *)&params,
            sizeof(params), kSecKeyEncodingRSAPublicParams);
    if (!key) {
        sslErrorLog("sslGetPubKeyFromBits: SecKeyCreateRSAPublicKey failed\n");
        return errSSLCrypto;
    }
#if SSL_DEBUG
    sslDebugLog("sslGetPubKeyFromBits: RSA pub key block size=%lu\n", SecKeyGetBlockSize(key));
#endif
    *pubKey = (SSLPubKey*)key;
    return errSecSuccess;
#endif
}

static DERSize DERLengthOfTag(
    DERTag tag)
{
    DERSize rtn = 1;

    tag &= ASN1_TAGNUM_MASK;
    if (tag >= 0x1F) {
        /* Shift 7-bit digits out of the tag integer until it's zero. */
        while(tag != 0) {
            rtn++;
            tag >>= 7;
        }
    }

    return rtn;
}

static DERReturn DEREncodeTag(
    DERTag tag,
    DERByte *buf,       /* encoded length goes here */
    DERSize *inOutLen)  /* IN/OUT */
{
    DERSize outLen = DERLengthOfTag(tag);
    DERTag tagNumber = tag & ASN1_TAGNUM_MASK;
    DERByte tag1 = (tag >> (sizeof(DERTag) * 8 - 8)) & 0xE0;

    if(outLen > *inOutLen) {
        return DR_BufOverflow;
    }

    if(outLen == 1) {
        /* short form */
        *buf = tag1 | tagNumber;
    }
    else {
        /* long form */
        DERByte *tagBytes = buf + outLen;   // l.s. digit of tag
        *buf = tag1 | 0x1F;                 // tag class / method indicator
        *--tagBytes = tagNumber & 0x7F;
        tagNumber >>= 7;
        while(tagNumber != 0) {
            *--tagBytes = (tagNumber & 0x7F) | 0x80;
            tagNumber >>= 7;
        }
    }
    *inOutLen = outLen;
    return DR_Success;
}

static DERSize DERLengthOfLength(
    DERSize length)
{
    DERSize rtn;
    
    if(length < 0x80) {
        /* short form length */
        return 1;
    }
    
    /* long form - one length-of-length byte plus length bytes */
    rtn = 1;
    while(length != 0) {
        rtn++;
        length >>= 8;
    }
    return rtn;
}

static /* calculate the content length of an encoded sequence */
DERSize DERContentLengthOfEncodedSequence(
    const void          *src,       /* generally a ptr to a struct full of 
                                     *    DERItems */
    DERShort            numItems,   /* size of itemSpecs[] */
    const DERItemSpec   *itemSpecs)
{
    DERSize contentLen = 0;
    unsigned dex;
    DERSize thisContentLen;
    
    /* find length of each item */
    for(dex=0; dex<numItems; dex++) {
        const DERItemSpec *currItemSpec = &itemSpecs[dex];
        DERShort currOptions = currItemSpec->options;
        const DERByte *byteSrc = (const DERByte *)src + currItemSpec->offset;
        const DERItem *itemSrc = (const DERItem *)byteSrc;

        if(currOptions & DER_ENC_WRITE_DER) {
            /* easy case - no encode */
            contentLen += itemSrc->length;
            continue;
        }
        
        if ((currOptions & DER_DEC_OPTIONAL) && itemSrc->length == 0) {
            /* If an optional item isn't present we don't encode a
               tag and len. */
            continue;
        }

        /* 
         * length of this item = 
         *   tag (one byte) +
         *   length of length +
         *   content length +
         *   optional zero byte for signed integer
         */
        contentLen += DERLengthOfTag(currItemSpec->tag);
        
        /* check need for pad byte before calculating lengthOfLength... */
        thisContentLen = itemSrc->length;
        if((currOptions & DER_ENC_SIGNED_INT) &&
           (itemSrc->length != 0)) {
            if(itemSrc->data[0] & 0x80) {
                /* insert zero keep it positive */
                thisContentLen++;
            }
        }
        contentLen += DERLengthOfLength(thisContentLen);
        contentLen += thisContentLen;
    }
    return contentLen;
}

static DERReturn DEREncodeLength(
    DERSize length,
    DERByte *buf,       /* encoded length goes here */
    DERSize *inOutLen)  /* IN/OUT */
{
    DERByte *lenBytes;
    DERSize outLen = DERLengthOfLength(length);
    
    if(outLen > *inOutLen) {
        return DR_BufOverflow;
    }
    
    if(length < 0x80) {
        /* short form */
        *buf = (DERByte)length;
        *inOutLen = 1;
        return DR_Success;
    }
    
    /* long form */
    *buf = (outLen - 1) | 0x80;     // length of length, long form indicator
    lenBytes = buf + outLen - 1;    // l.s. digit of length 
    while(length != 0) {
        *lenBytes-- = (DERByte)length;
        length >>= 8;
    }
    *inOutLen = outLen;
    return DR_Success;
}

static DERReturn DEREncodeSequence(
    DERTag              topTag,     /* ASN1_CONSTR_SEQUENCE, ASN1_CONSTR_SET */
    const void          *src,       /* generally a ptr to a struct full of 
                                     *    DERItems */
    DERShort            numItems,   /* size of itemSpecs[] */
    const DERItemSpec   *itemSpecs,
    DERByte             *derOut,    /* encoded data written here */
    DERSize             *inOutLen)  /* IN/OUT */
{
    const DERByte   *endPtr = derOut + *inOutLen;
    DERByte         *currPtr = derOut;
    DERSize         bytesLeft = *inOutLen;
    DERSize         contentLen;
    DERReturn       drtn;
    DERSize         itemLen;
    unsigned        dex;
    
    /* top level tag */
    itemLen = bytesLeft;
    drtn = DEREncodeTag(topTag, currPtr, &itemLen);
    if(drtn) {
        return drtn;
    }
    currPtr += itemLen;
    bytesLeft -= itemLen;
    if(currPtr >= endPtr) { 
        return DR_BufOverflow;
    }
    
    /* content length */
    contentLen = DERContentLengthOfEncodedSequence(src, numItems, itemSpecs);   
    itemLen = bytesLeft;
    drtn = DEREncodeLength(contentLen, currPtr, &itemLen);
    if(drtn) {
        return drtn;
    }
    currPtr += itemLen;
    bytesLeft -= itemLen;
    if(currPtr + contentLen > endPtr) {
        return DR_BufOverflow;
    }
    /* we don't have to check for overflow any more */
    
    /* grind thru the items */
    for(dex=0; dex<numItems; dex++) {
        const DERItemSpec *currItemSpec = &itemSpecs[dex];
        DERShort currOptions = currItemSpec->options;
        const DERByte *byteSrc = (const DERByte *)src + currItemSpec->offset;
        const DERItem *itemSrc = (const DERItem *)byteSrc;
        int prependZero = 0;
        
        if(currOptions & DER_ENC_WRITE_DER) {
            /* easy case */
            DERMemmove(currPtr, itemSrc->data, itemSrc->length);
            currPtr += itemSrc->length;
            bytesLeft -= itemSrc->length;
            continue;
        }

        if ((currOptions & DER_DEC_OPTIONAL) && itemSrc->length == 0) {
            /* If an optional item isn't present we skip it. */
            continue;
        }

        /* encode one item: first the tag */
        itemLen = bytesLeft;
        drtn = DEREncodeTag(currItemSpec->tag, currPtr, &itemLen);
        if(drtn) {
            return drtn;
        }
        currPtr += itemLen;
        bytesLeft -= itemLen;
        
        /* do we need to prepend a zero to content? */
        contentLen = itemSrc->length;
        if((currOptions & DER_ENC_SIGNED_INT) &&
           (itemSrc->length != 0)) {
            if(itemSrc->data[0] & 0x80) {
                /* insert zero keep it positive */
                contentLen++;
                prependZero = 1;
            }
        }

        /* encode content length */
        itemLen = bytesLeft;
        drtn = DEREncodeLength(contentLen, currPtr, &itemLen);
        if(drtn) {
            return drtn;
        }
        currPtr += itemLen;
        bytesLeft -= itemLen;
        
        /* now the content, with possible leading zero added */
        if(prependZero) {
            *currPtr++ = 0;
            bytesLeft--;
        }
        DERMemmove(currPtr, itemSrc->data, itemSrc->length);
        currPtr += itemSrc->length;
        bytesLeft -= itemSrc->length;
    }
    *inOutLen = (currPtr - derOut);
    return DR_Success;
}

static OSStatus sslEncodeDhParams(SSLBuffer        *blob,          /* data mallocd and RETURNED PKCS-3 encoded */
                           const SSLBuffer  *prime,         /* Wire format */
                           const SSLBuffer  *generator)     /* Wire format */
{
    OSStatus ortn = errSecSuccess;
    DER_DHParams derParams =
    {
        .p = {
            .length = prime->length,
            .data = prime->data,
        },
        .g = {
            .length = generator->length,
            .data = generator->data,
        },
        .l = {
            .length = 0,
            .data = NULL,
        }
    };

    DERSize ioLen = DH_ENCODED_PARAM_SIZE(derParams.p.length);
    DERByte *der = sslMalloc(ioLen);
    // FIXME: What if this fails - we should probably not have a malloc here ?
    assert(der);
    ortn = (OSStatus)DEREncodeSequence(ASN1_CONSTR_SEQUENCE,
                                       &derParams,
                                       DER_NumDHParamsItemSpecs, DER_DHParamsItemSpecs,
                                       der,
                                       &ioLen);
    // This should never fail

    blob->length=ioLen;
    blob->data=der;

    return ortn;
}

/*
 * Decode DH params and server public key.
 */
static OSStatus
SSLDecodeDHKeyParams(
    SSLContext *ctx,
    uint8_t **charPtr,      // IN/OUT
    size_t length)
{
    OSStatus        err = errSecSuccess;
    SSLBuffer       prime;
    SSLBuffer       generator;

    assert(ctx->protocolSide == kSSLClientSide);
    uint8_t *endCp = *charPtr + length;

    /* Allow reuse via renegotiation */
    SSLFreeBuffer(&ctx->dhPeerPublic);
    
    /* Prime, with a two-byte length */
    UInt32 len = SSLDecodeInt(*charPtr, 2);
    (*charPtr) += 2;
    if((*charPtr + len) > endCp) {
        return errSSLProtocol;
    }

    prime.data = *charPtr;
    prime.length = len;

    (*charPtr) += len;

    /* Generator, with a two-byte length */
    len = SSLDecodeInt(*charPtr, 2);
    (*charPtr) += 2;
    if((*charPtr + len) > endCp) {
        return errSSLProtocol;
    }

    generator.data = *charPtr;
    generator.length = len;

    (*charPtr) += len;

    sslEncodeDhParams(&ctx->dhParamsEncoded, &prime, &generator);

    /* peer public key, with a two-byte length */
    len = SSLDecodeInt(*charPtr, 2);
    (*charPtr) += 2;
    err = SSLAllocBuffer(&ctx->dhPeerPublic, len);
    if(err) {
        return err;
    }
    memmove(ctx->dhPeerPublic.data, *charPtr, len);
    (*charPtr) += len;

    dumpBuf("client peer pub", &ctx->dhPeerPublic);
    //  dumpBuf("client prime", &ctx->dhParamsPrime);
    //  dumpBuf("client generator", &ctx->dhParamsGenerator);

    return err;
}

/*
 * Decode ECDH params and server public key.
 */
static OSStatus
SSLDecodeECDHKeyParams(
    SSLContext *ctx,
    uint8_t **charPtr,      // IN/OUT
    size_t length)
{
    OSStatus        err = errSecSuccess;

    sslEcdsaDebug("+++ Decoding ECDH Server Key Exchange");

    assert(ctx->protocolSide == kSSLClientSide);
    uint8_t *endCp = *charPtr + length;

    /* Allow reuse via renegotiation */
    SSLFreeBuffer(&ctx->ecdhPeerPublic);

    /*** ECParameters - just a curveType and a named curve ***/

    /* 1-byte curveType, we only allow one type */
    uint8_t curveType = **charPtr;
    if(curveType != SSL_CurveTypeNamed) {
        sslEcdsaDebug("+++ SSLDecodeECDHKeyParams: Bad curveType (%u)\n", (unsigned)curveType);
        return errSSLProtocol;
    }
    (*charPtr)++;
    if(*charPtr > endCp) {
        return errSSLProtocol;
    }

    /* two-byte curve */
    ctx->ecdhPeerCurve = SSLDecodeInt(*charPtr, 2);
    (*charPtr) += 2;
    if(*charPtr > endCp) {
        return errSSLProtocol;
    }
    switch(ctx->ecdhPeerCurve) {
        case SSL_Curve_secp256r1:
        case SSL_Curve_secp384r1:
        case SSL_Curve_secp521r1:
            break;
        default:
            sslEcdsaDebug("+++ SSLDecodeECDHKeyParams: Bad curve (%u)\n",
                (unsigned)ctx->ecdhPeerCurve);
            return errSSLProtocol;
    }

    sslEcdsaDebug("+++ SSLDecodeECDHKeyParams: ecdhPeerCurve %u",
        (unsigned)ctx->ecdhPeerCurve);

    /*** peer public key as an ECPoint ***/

    /*
     * The spec says the the max length of an ECPoint is 255 bytes, limiting
     * this whole mechanism to a max modulus size of 1020 bits, which I find
     * hard to believe...
     */
    UInt32 len = SSLDecodeInt(*charPtr, 1);
    (*charPtr)++;
    if((*charPtr + len) > endCp) {
        return errSSLProtocol;
    }
    err = SSLAllocBuffer(&ctx->ecdhPeerPublic, len);
    if(err) {
        return err;
    }
    memmove(ctx->ecdhPeerPublic.data, *charPtr, len);
    (*charPtr) += len;

    dumpBuf("client peer pub", &ctx->ecdhPeerPublic);

    return err;
}

static OSStatus
SSLVerifySignedServerKeyExchangeTls12(SSLContext *ctx, SSLSignatureAndHashAlgorithm sigAlg, SSLBuffer signedParams,
                                 uint8_t *signature, UInt16 signatureLen)
{
    OSStatus        err;
    SSLBuffer       hashOut, hashCtx, clientRandom, serverRandom;
    uint8_t         hashes[SSL_MAX_DIGEST_LEN];
    SSLBuffer       signedHashes;
    uint8_t         *dataToSign;
    size_t          dataToSignLen;
    const HashReference *hashRef;
    SecAsn1AlgId        algId;

    signedHashes.data = 0;
    hashCtx.data = 0;

    clientRandom.data = ctx->clientRandom;
    clientRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;
    serverRandom.data = ctx->serverRandom;
    serverRandom.length = SSL_CLIENT_SRVR_RAND_SIZE;

    switch (sigAlg.hash) {
        case SSL_HashAlgorithmSHA1:
            hashRef = &SSLHashSHA1;
            algId.algorithm = CSSMOID_SHA1WithRSA;
            break;
        case SSL_HashAlgorithmSHA256:
            hashRef = &SSLHashSHA256;
            algId.algorithm = CSSMOID_SHA256WithRSA;
            break;
        case SSL_HashAlgorithmSHA384:
            hashRef = &SSLHashSHA384;
            algId.algorithm = CSSMOID_SHA384WithRSA;
            break;
        default:
            sslErrorLog("SSLVerifySignedServerKeyExchangeTls12: unsupported hash %d\n", sigAlg.hash);
            return errSSLProtocol;
    }


    dataToSign = hashes;
    dataToSignLen = hashRef->digestSize;
    hashOut.data = hashes;
    hashOut.length = hashRef->digestSize;

    if ((err = ReadyHash(hashRef, &hashCtx)) != 0)
        goto fail;
    if ((err = hashRef->update(&hashCtx, &clientRandom)) != 0)
        goto fail;
    if ((err = hashRef->update(&hashCtx, &serverRandom)) != 0)
        goto fail;
    if ((err = hashRef->update(&hashCtx, &signedParams)) != 0)
        goto fail;
    if ((err = hashRef->final(&hashCtx, &hashOut)) != 0)
        goto fail;

    if(sigAlg.signature==SSL_SignatureAlgorithmRSA) {
        err = sslRsaVerify(ctx,
                           ctx->peerPubKey,
                           &algId,
                           dataToSign,
                           dataToSignLen,
                           signature,
                           signatureLen);
    } else {
        err = sslRawVerify(ctx,
                           ctx->peerPubKey,
                           dataToSign,              /* plaintext */
                           dataToSignLen,           /* plaintext length */
                           signature,
                           signatureLen);
    }

    if(err) {
        sslErrorLog("SSLDecodeSignedServerKeyExchangeTls12: sslRawVerify "
                    "returned %d\n", (int)err);
        goto fail;
    }

fail:
    SSLFreeBuffer(&signedHashes);
    SSLFreeBuffer(&hashCtx);
    return err;

}

/*
 * Decode and verify a server key exchange message signed by server's
 * public key.
 */
static OSStatus
SSLDecodeSignedServerKeyExchange(SSLBuffer message, SSLContext *ctx)
{
    OSStatus        err;
    UInt16          modulusLen = 0, exponentLen = 0, signatureLen;
    uint8_t         *modulus = NULL, *exponent = NULL, *signature;
    bool            isRsa = true;

    assert(ctx->protocolSide == kSSLClientSide);

    if (message.length < 2) {
        sslErrorLog("SSLDecodeSignedServerKeyExchange: msg len error 1\n");
        return errSSLProtocol;
    }

    /* first extract the key-exchange-method-specific parameters */
    uint8_t *charPtr = message.data;
    uint8_t *endCp = charPtr + message.length;
    switch(ctx->selectedCipherSpecParams.keyExchangeMethod) {
        case SSL_RSA:
        case SSL_RSA_EXPORT:
            modulusLen = SSLDecodeInt(charPtr, 2);
            charPtr += 2;
            if((charPtr + modulusLen) > endCp) {
                sslErrorLog("signedServerKeyExchange: msg len error 2\n");
                return errSSLProtocol;
            }
            modulus = charPtr;
            charPtr += modulusLen;

            exponentLen = SSLDecodeInt(charPtr, 2);
            charPtr += 2;
            if((charPtr + exponentLen) > endCp) {
                sslErrorLog("signedServerKeyExchange: msg len error 3\n");
                return errSSLProtocol;
            }
            exponent = charPtr;
            charPtr += exponentLen;
            break;
#if APPLE_DH
        case SSL_DHE_DSS:
        case SSL_DHE_DSS_EXPORT:
            isRsa = false;
            /* and fall through */
        case SSL_DHE_RSA:
        case SSL_DHE_RSA_EXPORT:
            err = SSLDecodeDHKeyParams(ctx, &charPtr, message.length);
            if(err) {
                return err;
            }
            break;
        #endif  /* APPLE_DH */

        case SSL_ECDHE_ECDSA:
            isRsa = false;
            /* and fall through */
        case SSL_ECDHE_RSA:
            err = SSLDecodeECDHKeyParams(ctx, &charPtr, message.length);
            if(err) {
                return err;
            }
            break;
        default:
            assert(0);
            return errSSLInternal;
    }

    /* this is what's hashed */
    SSLBuffer signedParams;
    signedParams.data = message.data;
    signedParams.length = charPtr - message.data;

    SSLSignatureAndHashAlgorithm sigAlg;

    if (sslVersionIsLikeTls12(ctx)) {
        /* Parse the algorithm field added in TLS1.2 */
        if((charPtr + 2) > endCp) {
            sslErrorLog("signedServerKeyExchange: msg len error 499\n");
            return errSSLProtocol;
        }
        sigAlg.hash = *charPtr++;
        sigAlg.signature = *charPtr++;
    }

    signatureLen = SSLDecodeInt(charPtr, 2);
    charPtr += 2;
    if((charPtr + signatureLen) != endCp) {
        sslErrorLog("signedServerKeyExchange: msg len error 4\n");
        return errSSLProtocol;
    }
    signature = charPtr;

    if (sslVersionIsLikeTls12(ctx))
    {
        err = SSLVerifySignedServerKeyExchangeTls12(ctx, sigAlg, signedParams,
                                                    signature, signatureLen);
    } else {
        err = SSLVerifySignedServerKeyExchange(ctx, isRsa, signedParams,
                                               signature, signatureLen);
    }

    if(err)
        goto fail;

    /* Signature matches; now replace server key with new key (RSA only) */
    switch(ctx->selectedCipherSpecParams.keyExchangeMethod) {
        case SSL_RSA:
        case SSL_RSA_EXPORT:
        {
            SSLBuffer modBuf;
            SSLBuffer expBuf;

            /* first free existing peerKey */
            sslFreePubKey(&ctx->peerPubKey);                    /* no KCItem */

            /* and cook up a new one from raw bits */
            modBuf.data = modulus;
            modBuf.length = modulusLen;
            expBuf.data = exponent;
            expBuf.length = exponentLen;
            err = sslGetPubKeyFromBits(ctx,
                &modBuf,
                &expBuf,
                &ctx->peerPubKey);
            break;
        }
        case SSL_DHE_RSA:
        case SSL_DHE_RSA_EXPORT:
        case SSL_DHE_DSS:
        case SSL_DHE_DSS_EXPORT:
        case SSL_ECDHE_ECDSA:
        case SSL_ECDHE_RSA:
            break;                  /* handled above */
        default:
            assert(0);
    }
fail:
    return err;
}

static OSStatus
SSLDecodeDHanonServerKeyExchange(SSLBuffer message, SSLContext *ctx)
{
    OSStatus        err = errSecSuccess;

    assert(ctx->protocolSide == kSSLClientSide);
    if (message.length < 6) {
        sslErrorLog("SSLDecodeDHanonServerKeyExchange error: msg len %u\n",
            (unsigned)message.length);
        return errSSLProtocol;
    }
    uint8_t *charPtr = message.data;
    err = SSLDecodeDHKeyParams(ctx, &charPtr, message.length);
    if(err == errSecSuccess) {
        if((message.data + message.length) != charPtr) {
            err = errSSLProtocol;
        }
    }
    return err;
}

OSStatus
custom_SSLProcessServerKeyExchange(SSLBuffer message, SSLContext *ctx)
{
    OSStatus      err;
    
    switch (ctx->selectedCipherSpecParams.keyExchangeMethod) {
        case SSL_RSA:
        case SSL_RSA_EXPORT:
        #if     APPLE_DH
        case SSL_DHE_RSA:
        case SSL_DHE_RSA_EXPORT:
        case SSL_DHE_DSS:
        case SSL_DHE_DSS_EXPORT:
        #endif
        case SSL_ECDHE_ECDSA:
        case SSL_ECDHE_RSA:
            err = SSLDecodeSignedServerKeyExchange(message, ctx);
            break;
        #if     APPLE_DH
        case SSL_DH_anon:
        case SSL_DH_anon_EXPORT:
            err = SSLDecodeDHanonServerKeyExchange(message, ctx);
            break;
        #endif
        default:
            err = errSecUnimplemented;
            break;
    }

    return err;
}
