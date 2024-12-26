#!/usr/bin/env python3
# aes.py taken from https://github.com/boppreh/aes
# analyze_faults.py taken from https://github.com/TeamMolecule/f00dsimpleserial
from aes import AES
import sys
import binascii

TXT = binascii.unhexlify('11111111111111111111111111111111')

KEY256 = binascii.unhexlify('2222222222222222222222222222222222222222222222222222222222222222')
EXP256 = binascii.unhexlify('3EB1A231BA239126C56B638D5C926E8A')

KEY128 = KEY256[:16]
EXP128 = binascii.unhexlify('1A200A8C1670E1DD43198E69AB83084F')

KEY = KEY256
EXP = EXP256
ENCRYPT = False
THRESHOLD = 16
ONLYGOOD = False

def bits(x):
    n = 0
    for y in x:
        while y != 0:
            if y & 1:
                n += 1
            y = y >> 1
    return n

def find_fault_encrypt(log, akey=KEY):
    lastsum = 128
    lastr = 10 if len(akey) == 16 else 14
    lasts = 3
    for r in range(lastr, -1, -1):
        for s in range(3, -1, -1):
            if log[r][s] is None:
                continue
            diffsum = bits(log[r][s])
            if diffsum <= lastsum:
                lastsum = diffsum
                lastr = r
                lasts = s
    return (lastr, lasts)

def find_fault_decrypt(log, akey=KEY):
    lastsum = 128
    lastr = 0
    lasts = 3
    for r in range(0, 11 if len(akey) == 16 else 15):
        for s in range(0, 4):
            if log[r][s] is None:
                continue
            diffsum = bits(log[r][s])
            if diffsum <= lastsum:
                lastsum = diffsum
                lastr = r
                lasts = s
    return (lastr, lasts)

def parse(ct, offset, width, clk, akey=KEY, aexp=EXP, atxt=TXT, aencrypt=ENCRYPT, athreshold=THRESHOLD, aonlygood=ONLYGOOD):
    ctb = binascii.unhexlify(ct)
    aes = AES(akey)
    if aencrypt:
      log = aes.decrypt_diff(aexp, ctb)
      (r, s) = find_fault_encrypt(log)
    else:
      log = aes.encrypt_diff(atxt, ctb)
      (r, s) = find_fault_decrypt(log)
    diffsum = bits(log[r][s])
    if diffsum < athreshold:
        if aonlygood:
            print('{}'.format(ct))
        else:
            print('GOOD: vclk={}, offset={}, width={}, bits={}, round={}, before={}, {}'.format(clk, offset, width, diffsum, r, AES.Step(s).name, ct))
    elif not aonlygood:
        print('BAD: vclk={}, offset={}, width={}, bits={}, round={}, before={}'.format(clk, offset, width, diffsum, r, AES.Step(s).name))
    return r, s, diffsum

def unbox(line):
    if not "," in line: # raw/samples list mode
        return line.strip(), 0, 0, 0
    # make sure its a fault
    if "bad_decrypt" not in line:
        return None, None, None, None
    if "jig" in line:
        return None, None, None, None
    if len(KEY) == 16 and "key256=1" in line:
        return None, None, None, None
    elif len(KEY) == 32 and "key256=0" in line:
        return None, None, None, None
    offset = int(line.split("offset=")[1].split(",")[0])
    width = int(line.split("width=")[1].split(",")[0])
    if "vclk=" in line:
        clock = int(line.split("vclk=")[1].split(",")[0])
    else:
        clock = 2
    ct = line.split("data=")[1][:32]
    # discard if not hex
    try:
        binascii.unhexlify(ct)
    except:
        return None, None, None, None
    if ct == TXT.hex().upper():
        return None, None, None, None
    return ct, offset, width, clock

if __name__ == '__main__': # args: [-k key] [-e|-d] [-p plaintext] [-c ciphertext] [-t threshold] [-g] FILE
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == '-k':
            KEY = binascii.unhexlify(sys.argv[i+1])
        elif sys.argv[i] == '-e':
            ENCRYPT = True
        elif sys.argv[i] == '-d':
            ENCRYPT = False
        elif sys.argv[i] == '-p':
            TXT = binascii.unhexlify(sys.argv[i+1])
        elif sys.argv[i] == '-c':
            EXP = binascii.unhexlify(sys.argv[i+1])
        elif sys.argv[i] == '-t':
            THRESHOLD = int(sys.argv[i+1])
        elif sys.argv[i] == '-g':
            ONLYGOOD = True
        elif i == len(sys.argv) - 1:
            print(f"Analyzing {sys.argv[i]}")
            print(" key: {}".format(KEY.hex()))
            print(" encrypt: {}".format(ENCRYPT))
            print(" plaintext: {}".format(TXT.hex()))
            print(" ciphertext: {}".format(EXP.hex()))
            print(" threshold: {}".format(THRESHOLD))
            print(" only good: {}".format(ONLYGOOD))
            with open(sys.argv[i]) as fp:
                line = fp.readline()
                while line:
                    ct,o,w,c = unbox(line)
                    if ct is not None:
                        r,s,d = parse(ct, o, w, c, KEY, EXP, TXT, ENCRYPT, THRESHOLD, ONLYGOOD)
                        #print(f"would work on {ct}")
                    line = fp.readline()