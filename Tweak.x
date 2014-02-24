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

#include "minimal.h"

/* Minimal Cydia Substrate header */
typedef const void *MSImageRef;
MSImageRef MSGetImageByName(const char *file);
void *MSFindSymbol(MSImageRef image, const char *name);
void MSHookFunction(void *symbol, void *replace, void **result);

#define LIBRARY_PATH "/System/Library/Frameworks/Security.framework/Security"
#define LOAD_SYMBOL(name) do { \
    _ ## name = MSFindSymbol(image, "_" #name); \
    if (_ ## name == NULL) { \
        NSLog(@"SSLPatch: Failed to find symbol: " #name "."); \
        return; \
    } \
} while(0)

%ctor {
    MSImageRef image = NULL;
    void *_SSLProcessServerKeyExchange = NULL;

    image = MSGetImageByName(LIBRARY_PATH);
    if (image == NULL) {
        NSLog(@"SSLPatch: Failed to load Security framework.");
        return;
    }

    LOAD_SYMBOL(SSLProcessServerKeyExchange);
    LOAD_SYMBOL(CSSMOID_SHA1WithRSA);
    LOAD_SYMBOL(CSSMOID_SHA256WithRSA);
    LOAD_SYMBOL(CSSMOID_SHA384WithRSA);
    LOAD_SYMBOL(SSLHashMD5);
    LOAD_SYMBOL(SSLHashSHA1);
    LOAD_SYMBOL(SSLHashSHA256);
    LOAD_SYMBOL(SSLHashSHA384);
    LOAD_SYMBOL(SSLAllocBuffer);
    LOAD_SYMBOL(SSLFreeBuffer);
    LOAD_SYMBOL(SSLDecodeInt);
    LOAD_SYMBOL(sslFreePubKey);
    LOAD_SYMBOL(sslGetPubKeyFromBits);
    LOAD_SYMBOL(ReadyHash);
    LOAD_SYMBOL(SSLDecodeDHKeyParams);
    LOAD_SYMBOL(sslRsaVerify);
    LOAD_SYMBOL(sslRawVerify);

    MSHookFunction(_SSLProcessServerKeyExchange, custom_SSLProcessServerKeyExchange, NULL);
}
