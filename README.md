Patch Script For mshtml.dll  
---------------------------


### What for?

Microsoft introduced several mitigations in Internet Explorer, one of them is 
ProtectedFree. This feature may be disturbing if you are doing fuzzing or 
debugging. The purpose of this script is to patch mshtml.dll and optionally 
either disable protection, or customize freed memory pattern. Be aware that this 
script uses hard-coded values and may break your browser (unlikely however), 
therefore, use it at your own risk. I also do not recommend to use Internet 
Explorer for browsing after this patch.


### How to use this script?

Script accepts following arguments:

```
C:\Users\debug\Desktop>mshtml-patcher.py --help
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher, v.0.2.0
(Tested on Windows 7/8 x32/x64, IE9 - IE11 x32 bit versions)

usage: mshtml-patcher.py [-h]
                         (--patch-memset XX | --patch-disable | --restore | --print-info)
                         [--path-to-dll-default PATH]
                         [--path-to-dll-saved PATH] [--msver {9,10,11}]
                         [--md5-hash MD5_HASH]

optional arguments:
  -h, --help            show this help message and exit
  --patch-memset XX     patch memset
  --patch-disable       disable protection
  --restore             restore original file
  --print-info          only print information
  --path-to-dll-default PATH
                        override path to binary to patch
  --path-to-dll-saved PATH
                        override path to original binary
  --msver {9,10,11}     override major IE version
  --md5-hash MD5_HASH   override md5 file hash
```

This script will automatically find Internet Explorer version and path to 
mshtml.dll to patch. You can also specify them explicitly in arguments. Before 
patching, script creates file backup named "original-mshtml.dll". 

#####--patch-memset XX

Will patch memset arguments in MemoryProtection::CMemoryProtector::ProtectedFree 
so you can see some recognizable pattern instead of zeros. In place of XX put 
some hex value.


#####--patch-disable

Disables Memory Protection mitigation. 


#####--print-info

Print information about files.


#####--restore

Restore original (previously saved) dll file.


Script supports Internet Explorer version 9, 10, 11, only 32 bit binaries. 
Tested on Windows 7/8. 


### Important

To use this script, you need to have rights to modify mshtml.dll.

Please be aware that after update you have to move original-mshtml.dll file 
somewhere else, otherwise script will replace new mshtml.dll with older version.
The script will show versions of both files.


### Example

```
C:\Users\debug\Desktop>mshtml-patcher.py --patch-memset ba
--------------------------------------------------------------------------------
mshtml.dll Memory Protection Feature Patcher, v.0.2.0
(Tested on Windows 7/8 x32/x64, IE9 - IE11 x32 bit versions)

OS Version: Windows 7
Path to mshtml.dll: C:\Windows\System32\mshtml.dll
          md5 hash: 61c74d794c14e9fc94d93f5f0f72a3f9
           version: [11, 0, 9600, 17631]

Path to original-mshtml.dll: C:\Users\debug\Desktop\original-mshtml.dll
                   md5 hash: 61c74d794c14e9fc94d93f5f0f72a3f9
                    version: [11, 0, 9600, 17631]

WARNING: patching mshtml.dll binary may break it!

Do you wish to continue? (y/N)y

Restoring original file... (copying from C:\Users\debug\Desktop\original-mshtml.dll to C:\Windows\System32\mshtml.dll) done.

Will patch MemoryProtection::CMemoryProtector::ProtectedFree
Before:
+0x000735b4 d2 e0 08 04 1a 3b fe 72  dc 8b 7d 08 8b 5d f0 53
+0x000735c4 6a 00 57 e8 19 8c fd ff  83 c4 0c 5e 5f 5b 8b e5
+0x000735d4 5d c2 04 00 20 48 7d 63  70 13 71 63 90 13 71 63

Patching mshtml.dll with 0xba... done.

After:
+0x000735b4 d2 e0 08 04 1a 3b fe 72  dc 8b 7d 08 8b 5d f0 53
+0x000735c4 6a ba 57 e8 19 8c fd ff  83 c4 0c 5e 5f 5b 8b e5
+0x000735d4 5d c2 04 00 20 48 7d 63  70 13 71 63 90 13 71 63

```

