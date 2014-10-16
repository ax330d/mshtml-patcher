MSHTML.dll Patcher Script
=========================


What for?
---------

Recently MS introduced new mitigations in Internet Explorer, one of them is 
ProtectedFree. However, this feature may be disturbing if you are doing fuzzing 
or debugging. This script patches mshtml.dll and optionally can either disable 
protection or customize freed memory pattern. Be aware that this script uses 
some hardcoded values and may break your browser (unlikely), therefore, use it 
at your own risk. I also do not recommend to use Internet Explorer for browsing 
after this patch. (And before this patch.)


How to use it?
--------------

Script is pretty simple in use, accepts following aguments:

```
C:\Users\debug\Desktop>mshtml-patcher.py --help
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher, v.0.1.4
(Tested on Windows 7/8 x32/x64, IE9 - IE11 x32 bit versions)

usage: mshtml-patcher.py [-h]
                         (--patch-memset XX | --patch-disable | --restore)
                         [--path-to-binary PATH] [--path-to-original PATH]
                         [--msver {9,10,11}] [--md5-hash MD5_HASH]

optional arguments:
  -h, --help            show this help message and exit
  --patch-memset XX     patch memset
  --patch-disable       disable protection
  --restore             restore original file
  --path-to-binary PATH
                        path to binary to patch
  --path-to-original PATH
                        path to original binary
  --msver {9,10,11}     major IE version
  --md5-hash MD5_HASH   use provided md5 file hash
```

This script will automatically find MSIE version and path to mshtml.dll to 
patch. You can also specify them in arguments. Before patching, script creates 
file backup named "original-mshtml.dll".

######--patch-memset XX
Will patch memset arguments for 
MemoryProtection::CMemoryProtector::ProtectedFree so you can see some 
recognizable pattern instead of zeroes. In place of XX put some hex value (I 
prefer "ba" for example).

######--patch-disable
Disables Memory Protection feature. 


Script supports Internet Explorer version 9, 10, 11, only 32 bit binaries. 
Tested on Windows 7/8. 

To use this script, you need to have rights to modify mshtml.dll.

Please be aware that after update you have to move original-mshtml.dll file 
somewhere, otherwise script will replace new mshtml.dll with older version.

Example
-------

```
C:\Users\debug\Desktop>mshtml-patcher.py --patch-memset ba
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher, v.0.1.4
(Tested on Windows 7/8 x32/x64, IE9 - IE11 x32 bit versions)

OS Version: Windows 7
Path to mshtml.dll: C:\Windows\System32\mshtml.dll
mshtml.dll md5 hash: f91e55da404b834648a3b0a2477c10db
            version: [11, 0, 9600, 17344]
original-mshtml.dll md5 hash: f91e55da404b834648a3b0a2477c10db
                     version: [11, 0, 9600, 17344]

WARNING: patching mshtml.dll binary may break it!

Do you wish to continue? (y/N)y

Restoring original file... (copying from C:\Users\debug\Desktop\original-mshtml.dll to C:\Windows\System32\mshtml.dll) done.

Will patch MemoryProtection::CMemoryProtector::ProtectedFree
Before:
+0x007970a8 d2 e0 08 04 1a 3b fe 72  dc 8b 7d 08 8b 5d f0 53
+0x007970b8 6a 00 57 e8 39 64 8b ff  83 c4 0c 5f 5e 5b 8b e5
+0x007970c8 5d c2 04 00 a1 58 94 49  64 e9 6e ff ff ff 8b 4d

Patching mshtml.dll with 0xba... done.

After:
+0x007970a8 d2 e0 08 04 1a 3b fe 72  dc 8b 7d 08 8b 5d f0 53
+0x007970b8 6a ba 57 e8 39 64 8b ff  83 c4 0c 5f 5e 5b 8b e5
+0x007970c8 5d c2 04 00 a1 58 94 49  64 e9 6e ff ff ff 8b 4d
```

