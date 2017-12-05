import sys
import os
import re
import hashlib
import binascii

def md5(path_to_file):
    return hashlib.md5(open(path_to_file, 'rb').read()).hexdigest()

def crc32(path_to_file):
    buf = open(path_to_file, 'rb').read()
    buf = (binascii.crc32(buf) & 0xFFFFFFFF)
    return ("%08X" % buf).lower()

def main():
    try:
        hash_value, func, path_to_file = sys.argv[1], sys.argv[2], sys.argv[3]
    except IndexError:
        print 'err: you must pass 3 arguments - 0x00000112'
        return

    if len(sys.argv) > 4:
        print  'err: you must pass 3 arguments - 0x00000112'
        return

    if func not in ['-md5', '-crc32']:
        print 'err: you can pass only -md5 or -crc32 as a hash function - 0x00000002'
        return

    if not os.path.isfile(path_to_file):
        print 'err: you must pass a path to file as a third parameter 0x80000811'
        return

    calculated_hash_value = ''
    if func == '-crc32':
        if not re.findall(r'([a-fA-F\d]{8})', hash_value) or len(hash_value) != 8:
            print 'err: wrong crc32 format - 0x800008с2'
            return
        calculated_hash_value = crc32(path_to_file)
    elif func == '-md5':
        if not re.findall(r'([a-fA-F\d]{32})', hash_value) or len(hash_value) != 32:
            print 'err: wrong md5 format - 0x800008d5'
            return
        calculated_hash_value = md5(path_to_file)

    if hash_value.lower() == calculated_hash_value.lower():
        print 'success'
    else:
        print 'err: hashes don\'t match - 0x80000001'

if __name__ == '__main__':
    main()
