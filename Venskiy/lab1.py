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
        print 'err: you must pass 3 arguments'
        return

    if func not in ['-md5', '-crc32']:
        print 'err: you can pass only -md5 or -crc32 as a hash function'
        return

    if not os.path.isfile(path_to_file):
        print 'err: you must pass a path to file as a third parameter'
        return

    calculated_hash_value = ''
    if func == '-crc32':
        if not re.findall(r'([a-fA-F\d]{8})', hash_value):
            print 'err: wrong crc32 format'
            return
        calculated_hash_value = crc32(path_to_file)
    elif func == '-md5':
        if not re.findall(r'([a-fA-F\d]{32})', hash_value):
            print 'err: wrong md5 format'
            return
        calculated_hash_value = md5(path_to_file)

    if hash_value == calculated_hash_value:
        print 'success'
    else:
        print 'err: hashes don\'t match'

if __name__ == '__main__':
    main()
