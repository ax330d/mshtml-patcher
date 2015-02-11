#!c:\\python27\python.exe
# -*- coding: utf-8 -*-

"""

mshtml.dll patcher script.

Patches mshtml.dll to disable Protected Memory mitigation, or use some pattern
for memset after memory was freed.

Use this script only for debugging purposes.

By @ax330d.

"""


__version__ = '0.2.0'

import argparse
import os
import re
import struct
import shutil
import platform
import hashlib


def md5(path):
    """Find md5 hash of file."""
    with open(path, 'rb') as handle:
        md5_hash = hashlib.md5()
        while True:
            data = handle.read(8192)
            if not data:
                break
            md5_hash.update(data)
        return md5_hash.hexdigest()


class MSHTMLPatcher(object):
    """Class for patching mshtml.dll."""
    def __init__(self, path_to_dll_default, path_to_dll_saved, msver,
                 md5_hash):

        self._path_to_dll_default = path_to_dll_default
        self._path_to_dll_saved = path_to_dll_saved
        self._msver = msver
        self._md5_hash = md5_hash
        self._PATTERN_00 = ''
        self._PATTERN_02 = ''
        self._PATTERN_03 = ''
        self._saved_dll_name = 'original-mshtml.dll'

    def print_info(self):
        """Print information about dll and environment."""
        self.test_env(print_info=True)
        return

    def test_env(self, print_info=False):
        """Check OS, IE version, file access."""

        _, _, version, _, ptype, _ = platform.uname()

        if version not in ['7', 'post2008server', '8']:
            print "WARNING: Unsupported Windows version!"

        if ptype == 'AMD64':
            path_x86 = "C:\Windows\SysWOW64\mshtml.dll"
        elif ptype == 'x86':
            path_x86 = "C:\Windows\System32\mshtml.dll"
        else:
            print "WARNING: Unsupported processor type ({})!".format(ptype)
            return False

        dll_version = None
        if not self._msver:
            dll_version = self._get_dll_version(path_x86)
            if dll_version:
                self._msver, _, _, _ = dll_version
            else:
                self._msver = -1

        x86_md5hash = md5(path_x86)

        print "OS Version: Windows", version
        print "Path to mshtml.dll:", path_x86
        print "          md5 hash:", x86_md5hash
        print "           version:", dll_version
        print
        path_to_dll_saved = "{}\\{}".format(
            (os.path.dirname(os.path.abspath(__file__))),
            self._saved_dll_name)
        if self._path_to_dll_saved:
            path_to_dll_saved = self._path_to_dll_saved

        if os.path.isfile(path_to_dll_saved):
            print "Path to {}:".format(self._saved_dll_name), path_to_dll_saved
            x86_md5hash = md5(path_to_dll_saved)
            print "                   md5 hash:", x86_md5hash
            print "                    version:",
            print self._get_dll_version(path_to_dll_saved)
        print

        if self._msver < 9 or self._msver > 11:
            print "ERROR: Unsupported MSIE version!"
            return False

        if self._md5_hash:
            x86_md5hash = self._md5_hash

        patterns = self._get_patterns_base()
        if x86_md5hash not in patterns[self._msver]:
            print "ERROR: Pattern is missing for this binary!"
            return False

        self._PATTERN_00 = patterns[self._msver][x86_md5hash]['P00']
        self._PATTERN_02 = patterns[self._msver][x86_md5hash]['P02']
        self._PATTERN_03 = patterns[self._msver][x86_md5hash]['P03']

        if not self._path_to_dll_default:
            self._path_to_dll_default = path_x86

        if print_info:
            return True

        return True

    def patch_disable(self):
        """Will patch pushes/movs for MemoryProtection::DllNotification."""

        if not print_warning():
            return False
        if not self._test_file():
            return False

        print
        print "First patch for MemoryProtection::DllNotification"

        offset = self._find_offset(self._PATTERN_02)
        if not offset:
            return False
        print "Before:",
        self._hex_dump(offset)

        self._patch(offset + 1, 0x0)

        print "After:",
        self._hex_dump(offset)

        print
        print "Second patch for MemoryProtection::DllNotification"

        offset = self._find_offset(self._PATTERN_03)
        if not offset:
            return False
        print "Before:",
        self._hex_dump(offset)

        self._patch(offset + 1, 0x0)

        print "After:",
        self._hex_dump(offset)

        return True

    def patch_memset(self, what):
        """Will patch memset argument for
           MemoryProtection::CMemoryProtector::ProtectedFree."""

        if not print_warning():
            return
        if not self._test_file():
            return False

        print
        print "Will patch MemoryProtection::CMemoryProtector::ProtectedFree"

        offset = self._find_offset(self._PATTERN_00)
        if not offset:
            return False

        print "Before:",
        self._hex_dump(offset)

        self._patch(offset + 1, int(what[:2], 16))

        print "After:",
        self._hex_dump(offset)

        return True

    def restore(self, path_to_dll_saved=None):
        """Restore original (saved) file."""

        if not path_to_dll_saved:
            path_to_dll_saved = "{}\\{}".format(
                (os.path.dirname(os.path.abspath(__file__))),
                self._saved_dll_name)
        if self._path_to_dll_saved:
            path_to_dll_saved = self._path_to_dll_saved
        if not os.path.isfile(path_to_dll_saved):
            if not self._path_to_dll_saved:
                print "ERROR: Unable to find path to original (saved) file!"
                return False

        if not self._version_match(path_to_dll_saved,
                                   self._path_to_dll_default):
            return False

        print "Restoring original file...",

        if os.path.isfile(self._path_to_dll_default) and \
           os.path.isfile(path_to_dll_saved):
            print "(copying from {} to {})".format(path_to_dll_saved,
                                                   self._path_to_dll_default),
            shutil.copy2(path_to_dll_saved, self._path_to_dll_default)
        else:
            print "Some file is missing!"
            return False
        print "done."
        return True

    def _version_match(self, saved, current):
        """Check if file version matches."""

        orig_dll_version = self._get_dll_version(saved)
        new_dll_version = self._get_dll_version(current)
        if orig_dll_version and new_dll_version:
            if orig_dll_version[2] != new_dll_version[2] and \
               orig_dll_version[3] != new_dll_version[3]:
                print "ERROR: File versions do not match: {} vs {}!".format(
                    orig_dll_version, new_dll_version)
                return False
        return True

    def _hex_dump(self, offset):
        """Hex dump for files."""

        with file(self._path_to_dll_default, 'rb') as handle:
            handle.seek(offset - 0x10)
            block = handle.read(0x30)
            i = 0
            for byte in block:
                if (i % 16 == 0) or (i == 0):
                    print
                    print "+0x{:08x}".format(offset + i - 0x10),
                elif i % 8 == 0:
                    print '',
                print "{:02x}".format(ord(byte)),
                i += 1
        print
        return

    def _patch(self, index, patch_bytes):
        """Patch binary and save changes."""

        print
        print "Patching mshtml.dll with 0x{:02x}...".format(patch_bytes),

        with open(self._path_to_dll_default, 'r+b') as handle:
            handle.seek(index)
            handle.write(struct.pack('B', patch_bytes))
        print "done."
        print
        return

    def _test_file(self):
        """If file backup does not exists, creates one. If we are patching,
           reverts to original file to avoid collision with previous patch."""

        print
        if not self._path_to_dll_saved:
            path_to_dll_saved = "{}\\{}".format(
                (os.path.dirname(os.path.abspath(__file__))),
                self._saved_dll_name)
        else:
            path_to_dll_saved = self._path_to_dll_saved
        if not os.path.isfile(path_to_dll_saved):
            print "Backing up original file...",
            shutil.copy2(self._path_to_dll_default, path_to_dll_saved)
            print "({})".format(path_to_dll_saved),
            print "done."
        else:
            if not self.restore(path_to_dll_saved):
                return False
        return True

    def _find_offset(self, pattern):
        """Find offset for some pattern in binary."""

        with open(self._path_to_dll_default, 'rb') as handle:
            binary = handle.read()

        index = binary.find(pattern)
        if index == -1:
            print "Have not found pattern to patch!"
            return False

        rep = binary.find(pattern, index + 1)
        if rep != -1:
            print "Found two or more patterns, will not patch"
            return False
        return index

    @classmethod
    def _get_dll_version(cls, file_name):
        """Try to get DLL version."""

        handle = open(file_name, 'rb')
        data = handle.read().replace('\x00', '')
        handle.close()

        offset_str = data.rfind('StringFileInfo')
        if offset_str == -1:
            return False

        offset_var = data.rfind('VarFileInfo')
        if offset_var == -1:
            offset_var = offset_str + 512

        info = re.findall("FileVersion(.+?)\x01", data[offset_str:offset_var])
        if not len(info):
            return False

        match = re.match(r'(\d+\.\d+\.\d+\.\d+) (?:.*?)', info[0][:-2])
        if match:
            return map(int, match.group(1).split('.'))
        return False

    @classmethod
    def _get_patterns_base(cls):
        """Holds all patterns."""
        patterns = {}
        # Patterns for IE9
        patterns[9] = {
            'befe2a3b0fd950e895a623df4238247e': {
                'P00': "\x6a\x00\x57\xe8\x41\x4d\x95\xff",
                'P02': "\x6a\x02\xeb\x06\x8b\x4d\x10\x51",
                'P03': "\x6a\x03\x56\xe8\x9e\x38\x62\x00"
            },
            # IE9, update of 09-09-2014
            'b7e3af84d1cf6caa39ea69ef2734b517': {
                'P00': "\x6a\x00\x57\xe8\xdd\x25\x95\xff",
                'P02': "\x6a\x02\xeb\x06\x8b\x4d\x10\x51",
                'P03': "\x6a\x03\x56\xe8\x09\x60\x62\x00"
            },
            # IE9, update of 14-10-2014
            '3e7834cd2a543d58443bbe38fd74e8eb': {
                'P00': "\x6a\x00\x57\xe8\x5d\x22\x95\xff",
                'P02': "\x6a\x02\xeb\x06\x8b\x45\x10\x50",
                'P03': "\x6a\x03\x56\xe8\xdc\x63\x62\x00"
            },
            # IE9, update of 11-11-2014
            '5bdcc7129c2f0a25f8a8ff6a3bdd9896': {
                'P00': "\x6a\x00\x57\xe8\x35\x19\x95\xff",
                'P02': "\x6a\x02\xeb\x06\x8b\x45\x10\x50",
                'P03': "\x6a\x03\x56\xe8\x30\x6c\x62\x00"
            },
            # IE9, update of 09-12-2014
            '91f488c0ed1d8b1fdc112f95a4965cc6': {
                'P00': "\x6a\x00\x57\xe8\x5d\x0e\x95\xff",
                'P02': "\x6a\x02\xeb\x06\x8b\x45\x10\x50",
                'P03': "\x6a\x03\x56\xe8\xa1\x7a\x62\x00"
            },
            # IE9, update of 10-12-2014
            '88dfffe4a1c25c256a74629599292a2d': {
                'P00': "\x6a\x00\x57\xe8\x05\x0a\x95\xff",
                'P02': "\x6a\x02\xeb\x06\x8b\x45\x10\x50",
                'P03': "\x6a\x03\x56\xe8\x7c\x7e\x62\x00"
            }
        }

        # Patterns for IE10
        patterns[10] = {
            '59519c658518aa899b76aeefa7719112': {
                'P00': "\x6a\x00\x56\xe8\x53\xb4\x4d\xff",
                'P02': "\x6a\x02\x58\xe8\x06\xf1\x55\x00",
                'P03': "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
            },
            # IE10, update of 09-09-2014
            '9004d71ad5841653cc67f48b7428ec7d': {
                'P00': "\x6a\x00\x56\xe8\xbe\x46\x4d\xff",
                'P02': "\x6a\x02\x58\xe8\x08\x76\x56\x00",
                'P03': "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
            },
            # IE10, update of 14-10-2014
            '5cc7c09299a59efb3d39b919440e4d1b': {
                'P00': "\x6a\x00\x56\xe8\x79\x16\x4d\xff",
                'P02': "\x6a\x02\x58\xe8\xe6\x9a\x56\x00",
                'P03': "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
            },
            # IE10, update of 11-11-2014
            '9e693725f153cd9ef08e90d58ebebc54': {
                'P00': "\x6a\x00\x56\xe8\xa9\xe7\x4c\xff",
                'P02': "\x6a\x02\x58\xe8\xe1\xde\x56\x00",
                'P03': "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
            },
            # IE10, update of 09-12-2014
            '50f36baedf56ccc4367c975451479211': {
                'P00': "\x6a\x00\x56\xe8\xd9\x13\x4d\xff",
                'P02': "\x6a\x02\x58\xe8\xf3\xc8\x56\x00",
                'P03': "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
            },
            # IE10, update of 10-12-2014
            'c901a53bf5c517d9fc054905b52fbad0': {
                'P00': "\x6a\x00\x56\xe8\xf1\xdb\x4c\xff",
                'P02': "\x6a\x02\x58\xe8\xa8\xed\x56\x00",
                'P03': "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
            }
        }

        # Patterns for IE11
        patterns[11] = {
            '8453ddf167ce2986aa4ab04bc6824925': {
                'P00': "\x6a\x00\x57\xc6\x46\x10\x00\xe8"
                       "\x87\x6d\x8b\xff\x83\xc4\x0c\x5e",
                'P02': "\xba\x02\x00\x00\x00\xeb\x05\xba",
                'P03': "\xba\x03\x00\x00\x00\xff\x75\x10"
            },
            # IE11, update of 09-09-2014
            '7bf1ce9240cb9dd27c3e30733176eb8e': {
                'P00': "\x6a\x00\x57\xe8\x3b\xfb\x8a\xff"
                       "\x83\xc4\x0c\x5e\x5f\x5b\x8b\xe5",
                'P02': "\xba\x02\x00\x00\x00\xeb\x05\xba",
                'P03': "\xba\x03\x00\x00\x00\xff\x75\x10"
            },
            # IE11, update of 14-10-2014
            'f91e55da404b834648a3b0a2477c10db': {
                'P00': "\x6a\x00\x57\xe8\x39\x64\x8b\xff"
                       "\x83\xc4\x0c\x5f\x5e\x5b\x8b\xe5",
                'P02': "\xba\x02\x00\x00\x00\xeb\x05\xba",
                'P03': "\xba\x03\x00\x00\x00\xff\x75\x10"
            },
            # IE11, update of 11-11-2014
            '93074c4fa92a8399404d032f6af72c1b': {
                'P00': "\x6a\x00\x57\xe8\x19\x8c\xfd\xff"
                       "\x83\xc4\x0c\x5e\x5f\x5b\x8b\xe5",
                'P02': "\xba\x02\x00\x00\x00\xff\x75\x10",
                'P03': "\xba\x03\x00\x00\x00\xe9\xd8\xfe"
            },
            # IE11, update of 09-12-2014
            '220505b0b3e96c857dd01729af0cd369': {
                'P00': "\x6a\x00\x57\xe8\x19\x8c\xfd\xff"
                       "\x83\xc4\x0c\x5e\x5f\x5b\x8b\xe5",
                'P02': "\xba\x02\x00\x00\x00\xff\x75\x10",
                'P03': "\xba\x03\x00\x00\x00\xe9\xd8\xfe"
            },
            # IE11, update of 10-12-2014
            '61c74d794c14e9fc94d93f5f0f72a3f9': {
                'P00': "\x6a\x00\x57\xe8\x19\x8c\xfd\xff"
                       "\x83\xc4\x0c\x5e\x5f\x5b\x8b\xe5",
                'P02': "\xba\x02\x00\x00\x00\xff\x75\x10",
                'P03': "\xba\x03\x00\x00\x00\xe9\xd8\xfe"
            }
        }

        return patterns


def print_warning():
    """Warn about changes."""

    print "WARNING: patching mshtml.dll binary may break it!"
    print
    reply = raw_input("Do you wish to continue? (y/N)")
    if reply != 'y':
        return False
    return True


def main():
    """Main function. Parsgin arguments and starting patching."""

    print "-" * 80
    print "mshtml.dll Memory Protection Feature Patcher,",
    print "v.{}".format(__version__)
    print "(Tested on Windows 7/8 x32/x64, IE9 - IE11 x32 bit versions)"
    print

    args_parser = argparse.ArgumentParser()
    group = args_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--patch-memset", help="patch memset", metavar="XX")
    group.add_argument("--patch-disable", help="disable protection",
                       action='store_true')
    group.add_argument("--restore", help="restore original file",
                       action='store_true')
    group.add_argument("--print-info", help="only print information",
                       action='store_true')
    args_parser.add_argument("--path-to-dll-default", metavar="PATH",
                             help="override path to binary to patch")
    args_parser.add_argument("--path-to-dll-saved", metavar="PATH",
                             help="override path to original binary")
    args_parser.add_argument("--msver", help="override major IE version",
                             choices=[9, 10, 11], type=int)
    args_parser.add_argument("--md5-hash", help="override md5 file hash")

    args = args_parser.parse_args()
    patcher = MSHTMLPatcher(args.path_to_dll_default, args.path_to_dll_saved,
                            args.msver, args.md5_hash)

    if args.print_info:
        patcher.print_info()
        return

    if not patcher.test_env(args.print_info):
        return

    if args.patch_memset:
        patcher.patch_memset(args.patch_memset)
    elif args.patch_disable:
        patcher.patch_disable()
    elif args.restore:
        patcher.restore()
    else:
        args_parser.print_help()
    return


if __name__ == '__main__':
    main()
