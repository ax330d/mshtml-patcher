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
mshtml.dll Memory Protection Feature Patcher, v.0.1.2
(Tested on Windows 7 x32/x64, IE9 - IE11 x32 bit versions only)

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
recognizable pattern instead of zeroes. In place of XX put some hex value, I 
prefer "ba" for example.

######--patch-disable
Disables Memory Protection feature. 

Script supports Internet Explorer version 9, 10, 11, only 32 bit binaries. 
Tested on Windows 7. 

To use this script, you need to have rights to modify mshtml.dll.

Please be aware that after update you have to move original-mshtml.dll file 
somewhere, otherwise script will replace new mshtml.dll with older version.


Example
-------

```
C:\Users\debug\Desktop>mshtml-patcher.py --patch-memset ba
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher, v.0.1.2
(Tested on Windows 7 x32/x64, IE9 - IE11 x32 bit versions only)

OS Version: Windows 7
Path to mshtml.dll: C:\Windows\SysWOW64\mshtml.dll
MSIE version: 10
mshtml.dll md5 hash: 9004d71ad5841653cc67f48b7428ec7d

WARNING: patching mshtml.dll binary may break it!

Do you wish to continue? (y/N)y

Restoring original file before patching... done.

Will patch MemoryProtection::CMemoryProtector::ProtectedFree
Before:
+0x00b2efc7 47 24 50 8b 45 08 8b ce  e8 43 02 00 00 ff 75 08
+0x00b2efd7 6a 00 56 e8 be 46 4d ff  83 c4 0c 5f 5b 59 5d c2
+0x00b2efe7 04 00 90 90 90 90 90 8b  ff 55 8b ec 51 51 a1 98

Patching mshtml.dll with 0xba... done.

After:
+0x00b2efc7 47 24 50 8b 45 08 8b ce  e8 43 02 00 00 ff 75 08
+0x00b2efd7 6a ba 56 e8 be 46 4d ff  83 c4 0c 5f 5b 59 5d c2
+0x00b2efe7 04 00 90 90 90 90 90 8b  ff 55 8b ec 51 51 a1 98

```

