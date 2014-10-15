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
mshtml.dll Memory Protection Feature Patcher, v.0.1.3
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

Requirement: either "pefile" or "win32api" module.

Example
-------

```
C:\Users\debug\Desktop>mshtml-patcher.py --patch-memset ba
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher, v.0.1.3
(Tested on Windows 7/8 x32/x64, IE9 - IE11 x32 bit versions)

OS Version: Windows 7
Path to mshtml.dll: C:\Windows\SysWOW64\mshtml.dll
MSIE version: 9
mshtml.dll md5 hash: 3e7834cd2a543d58443bbe38fd74e8eb

WARNING: patching mshtml.dll binary may break it!

Do you wish to continue? (y/N)y

Restoring original file... (copying from C:\Users\debug\Desktop\original-mshtml.dll to C:\Windows\SysWOW64\mshtml.dll) done.

Will patch MemoryProtection::CMemoryProtector::ProtectedFree
Before:
+0x00a6ec80 1a ff 75 10 8d 4e 20 57  e8 b2 00 00 00 ff 75 10
+0x00a6ec90 6a 00 57 e8 5d 22 95 ff  83 c4 0c 5e 5f 5d c2 0c
+0x00a6eca0 00 90 90 90 90 90 8b ff  55 8b ec 80 7d 08 00 75

Patching mshtml.dll with 0xba... done.

After:
+0x00a6ec80 1a ff 75 10 8d 4e 20 57  e8 b2 00 00 00 ff 75 10
+0x00a6ec90 6a ba 57 e8 5d 22 95 ff  83 c4 0c 5e 5f 5d c2 0c
+0x00a6eca0 00 90 90 90 90 90 8b ff  55 8b ec 80 7d 08 00 75
```

