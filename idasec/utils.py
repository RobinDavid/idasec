import re

def register_name_to_size(reg):
    if reg in ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"]:
        return 8
    elif reg in ["ax", "bx", "cx", "dx", "di", "si", "bp", "sp"]:
        return 16
    elif reg in ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]:
        return 32
    elif reg in ["x87"]:
        return 80
    else:
        return -1

def to_hex(s):
    return "".join("{:02x}".format(ord(c)) for c in s)


def to_hex_spaced(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)

def hex_to_bin(s):
    s = s[2:] if s.startswith("0x") else s
    return ''.join([chr(int(x,16)) for x in hex_split(s)])

def hex_split(s):
    return [s[k:k+2] for k in xrange(0, len(s), 2)]


def to_addr(s): #raise ValueError if the conversion fail
    s = s.replace(" ", "")
    if s.endswith("L"):
        s = s[:-1]
    if not re.match('^[0-9a-fA-F]+$', s if not s.startswith("0x") else s[2:]):
        raise ValueError
    return int(s, 16) if s.startswith("0x") else int(s)