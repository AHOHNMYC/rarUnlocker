# rarUnlocker

*(c) AHOHNMYC, 2019. Distributed under WTFPL license*

RAR archives are support "locking" (not encryption!). You cannot edit locked archives, at least until you convert it or unpack and pack again.

This tool may set and unset "lock" flag in RAR4 and RAR5 archives (i hope, earlier too. Technotes for RAR2 looks like RAR4, sooo).

The only one exclusion is RAR5 with ecnrypted headers (option "Encrypt file names"). Flags are encrypted, so simple bytepatching is not possible without reimplementing AES256, and so on... I'm too lazy. And don't forget: RAR is proprietary format.

**This is not "cracker"!** RAR uses very strong encryption *(AES-256 with salt, password is encrypted with 2^18 iterations of PBKDF2 HMAC-SHA256)*. And nowadays may be broken only through bruteforcing.

### Compiling

[Windows build](/AHOHNMYC/rarUnlocker/releases)

`gcc rarUnlocker.c`, yep it's very primitive.

### Usage

`rarUnlocker file.rar` - unsets lock flag

`rarUnlocker -l file.rar` - sets lock flag

### Usefull linkus

* File format technotes: [RAR5](https://www.rarlab.com/technote.htm), [earlier](https://loc.gov/preservation/digital/formats/fdd/fdd000450.shtml#specs)

* [WinRAR site](https://rarlab.com)

* [WinRAR thread](https://forum.ru-board.com/topic.cgi?forum=5&topic=49002), Eugene Roshal answers here

![WinRAR](http://lurkmore.so/images/8/89/A_winrar_is_you.png)
