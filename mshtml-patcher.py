#
# mshtml.dll patcher script
#
# Patches mshtml.dll to disable Protected Memory feature, or use some pattern
# for memset after memory was freed.
#
# This is solely for debugging purpose.
#
# by @ax330d
#
# v 0.1     15-08-2014
# v 0.1.2   10-09-2014
# v 0.1.3   15-10-2014
# v 0.1.4   16-10-2014
# v 0.1.5   30-10-2014
# v 0.1.6   12-11-2014

__version__ = '0.1.6'

import argparse
import os
import re
import struct
import shutil
import struct
import platform
import hashlib


class AttributeDict(dict):
    """Implements access to dictionary elements through dot."""
    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value


def md5(path):
    """Find md5 hash of file."""
    with open(path, 'rb') as fh:
        m = hashlib.md5()
        while True:
            data = fh.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()


class MSHTMLPatcher(object):
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

        hb = int(what[:2], 16)
        self._patch(offset + 1, hb)

        print "After:",
        self._hex_dump(offset)

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

    def test_env(self, print_info=False):
        """Check OS, IE version, file access."""

        patterns = {}
        # Patterns for IE9
        patterns[9] = {}
        md5hash = 'befe2a3b0fd950e895a623df4238247e'
        patterns[9][md5hash] = AttributeDict()
        patterns[9][md5hash].P00 = "\x6a\x00\x57\xe8\x41\x4d\x95\xff"
        patterns[9][md5hash].P02 = "\x6a\x02\xeb\x06\x8b\x4d\x10\x51"
        patterns[9][md5hash].P03 = "\x6a\x03\x56\xe8\x9e\x38\x62\x00"
        # IE9, update of 09-09-2014
        md5hash = 'b7e3af84d1cf6caa39ea69ef2734b517'
        patterns[9][md5hash] = AttributeDict()
        patterns[9][md5hash].P00 = "\x6a\x00\x57\xe8\xdd\x25\x95\xff"
        patterns[9][md5hash].P02 = "\x6a\x02\xeb\x06\x8b\x4d\x10\x51"
        patterns[9][md5hash].P03 = "\x6a\x03\x56\xe8\x09\x60\x62\x00"
        # IE9, update of 14-10-2014
        md5hash = '3e7834cd2a543d58443bbe38fd74e8eb'
        patterns[9][md5hash] = AttributeDict()
        patterns[9][md5hash].P00 = "\x6a\x00\x57\xe8\x5d\x22\x95\xff"
        patterns[9][md5hash].P02 = "\x6a\x02\xeb\x06\x8b\x45\x10\x50"
        patterns[9][md5hash].P03 = "\x6a\x03\x56\xe8\xdc\x63\x62\x00"
        # IE9, update of 11-11-2014
        md5hash = '5bdcc7129c2f0a25f8a8ff6a3bdd9896'
        patterns[9][md5hash] = AttributeDict()
        patterns[9][md5hash].P00 = "\x6a\x00\x57\xe8\x35\x19\x95\xff"
        patterns[9][md5hash].P02 = "\x6a\x02\xeb\x06\x8b\x45\x10\x50"
        patterns[9][md5hash].P03 = "\x6a\x03\x56\xe8\x30\x6c\x62\x00"

        # Patterns for IE10
        patterns[10] = {}
        md5hash = '59519c658518aa899b76aeefa7719112'
        patterns[10][md5hash] = AttributeDict()
        patterns[10][md5hash].P00 = "\x6a\x00\x56\xe8\x53\xb4\x4d\xff"
        patterns[10][md5hash].P02 = "\x6a\x02\x58\xe8\x06\xf1\x55\x00"
        patterns[10][md5hash].P03 = "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
        # IE10, update of 09-09-2014
        md5hash = '9004d71ad5841653cc67f48b7428ec7d'
        patterns[10][md5hash] = AttributeDict()
        patterns[10][md5hash].P00 = "\x6a\x00\x56\xe8\xbe\x46\x4d\xff"
        patterns[10][md5hash].P02 = "\x6a\x02\x58\xe8\x08\x76\x56\x00"
        patterns[10][md5hash].P03 = "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
        # IE10, update of 14-10-2014
        md5hash = '5cc7c09299a59efb3d39b919440e4d1b'
        patterns[10][md5hash] = AttributeDict()
        patterns[10][md5hash].P00 = "\x6a\x00\x56\xe8\x79\x16\x4d\xff"
        patterns[10][md5hash].P02 = "\x6a\x02\x58\xe8\xe6\x9a\x56\x00"
        patterns[10][md5hash].P03 = "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
        # IE10, update of 11-11-2014
        md5hash = '9e693725f153cd9ef08e90d58ebebc54'
        patterns[10][md5hash] = AttributeDict()
        patterns[10][md5hash].P00 = "\x6a\x00\x56\xe8\xa9\xe7\x4c\xff"
        patterns[10][md5hash].P02 = "\x6a\x02\x58\xe8\xe1\xde\x56\x00"
        patterns[10][md5hash].P03 = "\x6a\x03\xeb\x05\xff\x75\x10\x6a"

        # Patterns for IE11
        patterns[11] = {}
        md5hash = '8453ddf167ce2986aa4ab04bc6824925'
        patterns[11][md5hash] = AttributeDict()
        patterns[11][md5hash].P00 = "\x6a\x00\x57\xc6\x46\x10\x00\xe8" \
                                    "\x87\x6d\x8b\xff\x83\xc4\x0c\x5e"
        patterns[11][md5hash].P02 = "\xba\x02\x00\x00\x00\xeb\x05\xba"
        patterns[11][md5hash].P03 = "\xba\x03\x00\x00\x00\xff\x75\x10"
        # IE11, update of 09-09-2014
        md5hash = '7bf1ce9240cb9dd27c3e30733176eb8e'
        patterns[11][md5hash] = AttributeDict()
        patterns[11][md5hash].P00 = "\x6a\x00\x57\xe8\x3b\xfb\x8a\xff" \
                                    "\x83\xc4\x0c\x5e\x5f\x5b\x8b\xe5"
        patterns[11][md5hash].P02 = "\xba\x02\x00\x00\x00\xeb\x05\xba"
        patterns[11][md5hash].P03 = "\xba\x03\x00\x00\x00\xff\x75\x10"
        # IE11, update of 14-10-2014
        md5hash = 'f91e55da404b834648a3b0a2477c10db'
        patterns[11][md5hash] = AttributeDict()
        patterns[11][md5hash].P00 = "\x6a\x00\x57\xe8\x39\x64\x8b\xff" \
                                    "\x83\xc4\x0c\x5f\x5e\x5b\x8b\xe5"
        patterns[11][md5hash].P02 = "\xba\x02\x00\x00\x00\xeb\x05\xba"
        patterns[11][md5hash].P03 = "\xba\x03\x00\x00\x00\xff\x75\x10"
        # IE11, update of 11-11-2014
        md5hash = '93074c4fa92a8399404d032f6af72c1b'
        patterns[11][md5hash] = AttributeDict()
        patterns[11][md5hash].P00 = "\x6a\x00\x57\xe8\x19\x8c\xfd\xff" \
                                    "\x83\xc4\x0c\x5e\x5f\x5b\x8b\xe5"
        patterns[11][md5hash].P02 = "\xba\x02\x00\x00\x00\xff\x75\x10"
        patterns[11][md5hash].P03 = "\xba\x03\x00\x00\x00\xe9\xd8\xfe"

        name, _, version, _, ptype, _ = platform.uname()

        if name != 'Windows':
            print "Not supported OS!"
            return False

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

        if x86_md5hash not in patterns[self._msver]:
            print "ERROR: Tested pattern is missing for this binary hash!"
            return False

        self._PATTERN_00 = patterns[self._msver][x86_md5hash].P00
        self._PATTERN_02 = patterns[self._msver][x86_md5hash].P02
        self._PATTERN_03 = patterns[self._msver][x86_md5hash].P03

        if not self._path_to_dll_default:
            self._path_to_dll_default = path_x86

        if print_info:
            return False

        return True

    def _hex_dump(self, offset):
        """Hex dump for files."""

        with file(self._path_to_dll_default, 'rb') as fh:
            fh.seek(offset - 0x10)
            block = fh.read(0x30)
            i = 0
            for b in block:
                if (i % 16 == 0) or (i == 0):
                    print
                    print "+0x{:08x}".format(offset + i - 0x10),
                elif i % 8 == 0:
                    print '',
                print "{:02x}".format(ord(b)),
                i += 1
        print
        return

    def _patch(self, index, hb):
        """Patch binary and save changes."""

        print
        print "Patching mshtml.dll with 0x{:02x}...".format(hb),

        with open(self._path_to_dll_default, 'r+b') as fh:
            fh.seek(index)
            fh.write(struct.pack('B', hb))
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

        with open(self._path_to_dll_default, 'rb') as f:
            bin = f.read()

        index = bin.find(pattern)
        if index == -1:
            print "Have not found pattern to patch!"
            return False

        rep = bin.find(pattern, index + 1)
        if rep != -1:
            print "Found two or more patterns, will not patch"
            return False
        return index

    def _get_dll_version(self, file):
        """Try to get DLL version."""

        fh = open(file, 'rb')
        data = fh.read().replace('\x00', '')
        fh.close()

        offset_str = data.rfind('StringFileInfo')
        if offset_str == -1:
            return False

        offset_var = data.rfind('VarFileInfo')
        if offset_var == -1:
            offset_var = offset_str + 512

        info = re.findall("FileVersion(.+?)\x01", data[offset_str:offset_var])
        if not len(info):
            return False

        m = re.match(r'(\d+\.\d+\.\d+\.\d+) (?:.*?)', info[0][:-2])
        if m:
            return map(int, m.group(1).split('.'))
        return False


def print_warning():
    """Warn about changes."""

    print "WARNING: patching mshtml.dll binary may break it!"
    print
    reply = raw_input("Do you wish to continue? (y/N)")
    if reply != 'y':
        return False
    return True


def main():

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
