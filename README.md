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
after this patch. And before this patch.


How to use it?
--------------

Script is pretty simple in use, just run without arguments and help will pop up.

```
C:\Users\Arthur\Documents\GitHub\mshtml-patch>mshtml-patcher.py
-------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher
(Tested on Windows 7 x32/x64, IE9 - IE11 x32 bit versions only)

OS Version: Windows 7
Path to mshtml.dll: C:\Windows\SysWOW64\mshtml.dll
MSIE version: 9

usage: mshtml-patcher.py [-h] [--patch-memset XX] [--patch-disable]
                         [--restore] [--path-to-binary PATH]
                         [--path-to-original PATH] [--msver {9,10,11}]

optional arguments:
  -h, --help            show this help message and exit
  --patch-memset XX     Patch memset
  --patch-disable       Disable protection
  --restore             Restore original file
  --path-to-binary PATH
                        Path to binary to patch
  --path-to-original PATH
                        Path to original binary
  --msver {9,10,11}     IE version

```

This script will automatically find MSIE version, and path to mshtml.dll to 
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


Example
-------

```
C:\Users\Arthur\Desktop>ms-patch.py --patch-memset ba
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher
(Tested on Windows 7 x32/x64, IE9 - IE11 x32 bit versions only)

OS Version: Windows 7
Path to mshtml.dll: C:\Windows\SysWOW64\mshtml.dll
MSIE version: 9

WARNING: patching mshtml.dll binary may break it!

Do you wish to continue? (y/N)y

Restoring original file before patching... done.

Will patch MemoryProtection::CMemoryProtector::ProtectedFree
Before:
+0x00a6d35c 00 84 c0 75 08 ff 15 ec  14 58 63 eb 0e ff 75 10
+0x00a6d36c 6a 00 57 e8 41 4d 95 ff  83 c4 0c 5e 5f 5d c2 0c
+0x00a6d37c 00 90 90 90 90 90 8b ff  55 8b ec 80 7d 08 00 75

Patching mshtml.dll with 0xba... done

After:
+0x00a6d35c 00 84 c0 75 08 ff 15 ec  14 58 63 eb 0e ff 75 10
+0x00a6d36c 6a ba 57 e8 41 4d 95 ff  83 c4 0c 5e 5f 5d c2 0c
+0x00a6d37c 00 90 90 90 90 90 8b ff  55 8b ec 80 7d 08 00 75
```

