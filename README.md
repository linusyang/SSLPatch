# SSL Patch (CVE-2014-1266)
Copyright (c) 2014 Linus Yang

Introduction
------
__CVE-2014-1266__, or known as "`goto fail` SSL verification exploit", is a very serious SSL/TLS vulnerability of iOS and OS X. Apple issues iOS 6.1.6 and 7.0.6 to fix this problem, but ignores some users who can't or just don't want to upgrade their systems to iOS 7 (e.g. users with older devices, or iOS 7 haters :P).

Finally, here is an elegant solution, especially for iOS jailbreak users: a Cydia Substrate tweak for fixing this SSL vulnerability. This tweak is a _runtime patch_ that __won't modify any system files__, so very __safe__ to use.

To install this fix, you can
  
  * Add repo [http://yangapp.googlecode.com/svn](http://yangapp.googlecode.com/svn) to Cydia, then search and install "SSL Patch",
  * Or manually download at the [Release Tab](https://github.com/linusyang/SSLPatch/releases) and install by iFile or dpkg.

After installation, you can use Safari to verify if the fix works by visiting following sites:

  * "Goto Fail": [gotofail.com](https://gotofail.com)
  * "Adam Langley's Weblog": [imperialviolet.org](https://www.imperialviolet.org:1266) (_If Safari can't open this page, it means the fix works._)

If you find any issue after installing this tweak, just uninstall it in Cydia.

Reference
------
[Adam Langley's Writeup](https://www.imperialviolet.org/2014/02/22/applebug.html)

[Apple OpenSource Library](http://opensource.apple.com/source/Security/Security-55471/libsecurity_ssl/lib/sslKeyExchange.c)

Build
------
```Bash
git clone --recursive https://github.com/linusyang/SSLPatch.git
cd SSLPatch
make
make package # If you have dpkg-deb utilities
```

License
------
Licensed under [GPLv3](http://www.gnu.org/copyleft/gpl.html).
