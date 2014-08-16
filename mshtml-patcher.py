#
# mshtml.dll patcher script
#
# Patches mshtml.dll library to disable Protected Memory feature, or use some
# pattern for memset after memory was freed.
#
# This is solely for debugging purpose.
#
# by @ax330d, 15-08-2014, v. 0.1.
#

import argparse
import os
import struct
import shutil
import struct
import platform


class AttributeDict(dict):
    """Implements access to dictionary elements through dot."""
    def __getattr__(self, attr):
        return self[attr]

    def __setattr__(self, attr, value):
        self[attr] = value


class MSHTMLPatcher(object):
    def __init__(self, binary_path, msver):

        self.path = binary_path
        self.msver = msver
        self._PATTERN_00 = ''
        self._PATTERN_02 = ''
        self._PATTERN_03 = ''

    def patch_disable(self):
        """Will patch pushes/movs for MemoryProtection::DllNotification."""

        if not print_warning():
            return
        self._test_file()

        print
        print "First patch for MemoryProtection::DllNotification"

        offset = self._find_offset(self._PATTERN_02)
        if not offset:
            return
        print "Before:",
        self._hex_dump(offset)

        self._patch(offset + 1, 0x0)

        print "After:",
        self._hex_dump(offset)

        print
        print "Second patch for MemoryProtection::DllNotification"

        offset = self._find_offset(self._PATTERN_03)
        if not offset:
            return
        print "Before:",
        self._hex_dump(offset)

        self._patch(offset + 1, 0x0)

        print "After:",
        self._hex_dump(offset)

        return

    def patch_memset(self, what):
        """Will patch memset argument for
           MemoryProtection::CMemoryProtector::ProtectedFree."""

        if not print_warning():
            return
        self._test_file()

        print
        print "Will patch MemoryProtection::CMemoryProtector::ProtectedFree"

        offset = self._find_offset(self._PATTERN_00)
        if not offset:
            return

        print "Before:",
        self._hex_dump(offset)

        hb = int(what[:2], 16)
        self._patch(offset + 1, hb)

        print "After:",
        self._hex_dump(offset)

        return

    def restore(self, original):
        """Restore original file."""

        if os.path.isfile(self.path) and os.path.isfile(original):
            print "Copying from {} to {}...".format(original, self.path),
            shutil.copy2(original, self.path)
        else:
            print "Some file is missing!"
            return False
        print "done"
        return True

    def test_env(self):
        """Check OS, IE version."""

        patterns = {}
        # Patterns for IE9
        patterns[9] = AttributeDict()
        patterns[9].P00 = "\x6a\x00\x57\xe8\x41\x4d\x95\xff"
        patterns[9].P02 = "\x6a\x02\xeb\x06\x8b\x4d\x10\x51"
        patterns[9].P03 = "\x6a\x03\x56\xe8\x9e\x38\x62\x00"
        # Patterns for IE10
        patterns[10] = AttributeDict()
        patterns[10].P00 = "\x6a\x00\x56\xe8\x53\xb4\x4d\xff"
        patterns[10].P02 = "\x6a\x02\x58\xe8\x06\xf1\x55\x00"
        patterns[10].P03 = "\x6a\x03\xeb\x05\xff\x75\x10\x6a"
        # Patterns for IE11
        patterns[11] = AttributeDict()
        patterns[11].P00 = "\x6a\x00\x57\xc6\x46\x10\x00\xe8" \
                           "\x87\x6d\x8b\xff\x83\xc4\x0c\x5e"
        patterns[11].P02 = "\xba\x02\x00\x00\x00\xeb\x05\xba"
        patterns[11].P03 = "\xba\x03\x00\x00\x00\xff\x75\x10"

        name, domain, version, release, ptype, etc = platform.uname()

        if name != 'Windows':
            print "Not supported OS!"
            return False

        if version != '7':
            print "WARNING: Unsupported Windows version!"

        if ptype == 'AMD64':
            path_x86 = "C:\Windows\SysWOW64\mshtml.dll"
            path_x64 = "C:\Windows\System32\mshtml.dll"
            ins = "C:\Program Files (x86)\Internet Explorer\SIGNUP\install.ins"
        elif ptype == 'x86':
            path_x86 = "C:\Windows\System32\mshtml.dll"
            path_x64 = None
            ins = "C:\Program Files\Internet Explorer\SIGNUP\install.ins"
        else:
            print "WARNING: Unsupported processor type!"

        if not self.msver:
            with open(ins, 'r') as fh:
                lines = fh.readlines()
                n, v = lines[3].split('=')
                mv = v.split(',')[0].replace('\x00', '')
            self.msver = int(mv)

        if self.msver < 9 or self.msver > 11:
            print "WARNING: Unsupported MSIE version!"

        self._PATTERN_00 = patterns[self.msver].P00
        self._PATTERN_02 = patterns[self.msver].P02
        self._PATTERN_03 = patterns[self.msver].P03

        print "OS Version: Windows", version
        print "Path to mshtml.dll:", path_x86
        print "MSIE version:", self.msver
        print
        if not self.path:
            self.path = path_x86

        return True

    def _hex_dump(self, offset):
        """Hex dump for files."""

        with file(self.path, 'rb') as fh:
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

        with open(self.path, 'r+b') as fh:
            fh.seek(index)
            fh.write(struct.pack('B', hb))
        print "done"
        print
        return

    def _test_file(self):
        """If file backup does not exists, creates one. If we are patching,
           reverts to original file to avoid collision with other patches."""

        print
        new_name = "%s\\original-mshtml.dll" % \
            (os.path.dirname(os.path.abspath(__file__)))
        if not os.path.isfile(new_name):
            print "Backing up original file...",
            shutil.copy2(self.path, new_name)
            print "{}".format(new_name)
            print "done."
        else:
            print "Restoring original file before patching...",
            # Rever to original file to patch it
            shutil.copy2(new_name, self.path)
            print "done."
        return

    def _find_offset(self, pattern):
        """Find offset for some pattern in binary."""

        with open(self.path, 'rb') as f:
            code = f.read()

        index = code.find(pattern)
        if index == -1:
            print "Have not found pattern to patch!"
            return False

        rep = code.find(pattern, index + 1)
        if rep != -1:
            print "Found two or more patterns, will not patch"
            return False
        return index


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
    print "mshtml.dll Memory Protection Feature Patcher"
    print "(Tested on Windows 7 x32/x64, IE9 - IE11 x32 bit versions only)"
    print

    args_parser = argparse.ArgumentParser()

    args_parser.add_argument("--patch-memset", help="Patch memset",
                             metavar="XX")
    args_parser.add_argument("--patch-disable", help="Disable protection",
                             action='store_true')
    args_parser.add_argument("--restore", help="Restore original file",
                             action='store_true')
    args_parser.add_argument("--path-to-binary", metavar="PATH",
                             help="Path to binary to patch")
    args_parser.add_argument("--path-to-original", metavar="PATH",
                             help="Path to original binary")
    args_parser.add_argument("--msver", help="IE version", choices=[9, 10, 11],
                             type=int)

    args = args_parser.parse_args()
    patcher = MSHTMLPatcher(args.path_to_binary, args.msver)
    if not patcher.test_env():
        return

    if args.patch_memset:
        patcher.patch_memset(args.patch_memset)
    elif args.patch_disable:
        patcher.patch_disable()
    elif args.restore:
        assumed_path = "%s\\original-mshtml.dll" % \
            (os.path.dirname(os.path.abspath(__file__)))
        if not os.path.isfile(assumed_path):
            if not args.path_to_original:
                print "Unable to find path to original file!"
                args_parser.print_help()
                return
            else:
                path = args.path_to_original
        else:
            path = assumed_path
        patcher.restore(path)
    else:
        args_parser.print_help()
    return


if __name__ == '__main__':
    main()
