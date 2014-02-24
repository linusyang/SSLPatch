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

#include "minimal.h"

// Interpose
#define CSSMOID_SHA1WithRSA (*_CSSMOID_SHA1WithRSA)
#define CSSMOID_SHA256WithRSA (*_CSSMOID_SHA256WithRSA)
#define CSSMOID_SHA384WithRSA (*_CSSMOID_SHA384WithRSA)

#define SSLHashMD5 (*_SSLHashMD5)
#define SSLHashSHA1 (*_SSLHashSHA1)
#define SSLHashSHA256 (*_SSLHashSHA256)
#define SSLHashSHA384 (*_SSLHashSHA384)

#define SSLAllocBuffer (*_SSLAllocBuffer)
#define SSLFreeBuffer (*_SSLFreeBuffer)
#define SSLDecodeInt (*_SSLDecodeInt)
#define sslFreePubKey (*_sslFreePubKey)
#define sslGetPubKeyFromBits (*_sslGetPubKeyFromBits)
#define ReadyHash (*_ReadyHash)
#define SSLDecodeDHKeyParams (*_SSLDecodeDHKeyParams)
#define sslRsaVerify (*_sslRsaVerify)
#define sslRawVerify (*_sslRawVerify)

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
/*      goto fail; (Oops, epic fail!) */
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
