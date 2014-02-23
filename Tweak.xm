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

#import <substrate.h>
#import "internal.h"

// @rpetrich's header files missing some Cydia Substrate functions
extern "C" {
    typedef const void *MSImageRef;
    MSImageRef MSGetImageByName(const char *file);
    void *MSFindSymbol(MSImageRef image, const char *name);
}

#define LIBRARY_PATH "/System/Library/Frameworks/Security.framework/Security"
#define SYMBOL_NAME "_SSLProcessServerKeyExchange"

%ctor {
    MSImageRef image;
    OSStatus (*func)(SSLBuffer message, SSLContext *ctx);

    image = MSGetImageByName(LIBRARY_PATH);
    func = reinterpret_cast<OSStatus (*)(SSLBuffer message, SSLContext *ctx)>(MSFindSymbol(image, SYMBOL_NAME));

    if (func != NULL) {
        MSHookFunction(func, custom_SSLProcessServerKeyExchange);
    }
}
