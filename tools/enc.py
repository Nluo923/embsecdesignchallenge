from Crypto.Hash import MD5, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from crypto_utils import xor
import itertools
from pwn import *
from string import ascii_uppercase, ascii_letters
from pycipher import Vigenere, Railfence, Caesar, Enigma
import random

MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}

alphabet = ascii_uppercase.encode("utf");
MORSE_TO_10 = {k: (lambda y: y.replace("-", "1"))((lambda x: x.replace(".", "0"))(v)) for k, v in MORSE_CODE_DICT.items()};
u10_TO_MORSE = {v: k for (k, v) in MORSE_TO_10.items()};

def step1(num):
    l = [];
    for i in range(num):
        hasher = MD5.new(get_random_bytes(16)).hexdigest();
        flag = f"embsec{{flag_{hasher}}}"
        l += [flag];
    return l

def step1msg(num):
    l = [];
    for i in range(num):
        hasher = SHA256.new(get_random_bytes(16)).hexdigest();
        flag = hasher + hasher[:20];
        l += [flag];
    return l

def step11(flag, n):
    rand = random.randint(1, n);
    flags = step1(rand-1) + [flag] + step1(n-rand);
    assert(len(flags) == n);
    flags += [str(rand) + "-"*(len(flag)-len(str(rand)))];
    
    return flags;

def step11msg(flag, n):
    rand = random.randint(1, n);
    flags = step1msg(rand-1) + [flag] + step1msg(n-rand);
    assert(len(flags) == n);
    flags += [str(rand) + "-"*(84-len(str(rand)))];
    
    return flags;


def step2(s, key):
    return Caesar(key=key).encipher(s, keep_punct=True).lower();


def step3(s, key):
    return Railfence(key).encipher(s, keep_punct=True).lower();
    
def step4(s, key):
    ans = b""
    s = s.upper().encode("utf");
    key = key.upper().encode("utf");
    alphabet = ascii_uppercase.encode("utf");
    for a, b in zip(s, itertools.cycle(key)):
        if not a in alphabet:
            ans += p8(a);
        else:
            val1 = a - 65;
            val2 = b - 65;
            ans += p8(((val1 + val2) % 26) + 65);
    return ans.decode("utf").lower();

    
def step5(s):
    en = Enigma(
        settings=("J", "A", "Y"),
        ringstellung=("D", "E", "N")
    );
    ans = "";
    for char in s:
        if char in ascii_letters:
            ans += en.encipher(char);
        else:
            ans += char;
    return ans.lower();
  
    
def step6(s, key, iv):
    b = s.encode("utf");
    aes = AES.new(key, AES.MODE_CBC, iv=iv);
    encrypted = aes.encrypt(pad(b, 16));   
    return encrypted.hex();

def step7(s):   
    ans = "";
    s = s.upper();
    for char in s:
        if char in MORSE_TO_10:
            ans += MORSE_TO_10[char];
        else:
            ans += char;
        ans += " ";
    return ans[:-1];

def step8(s, l, r):
    s = s.replace(" ", "".join([str(random.randint(0, 1)) for i in range(l)] + ["."] + [str(random.randrange(0, 1)) for i in range(r)]));
    return s;

def encryption(flag, n):
    return [step6(step5(step4(step3(step2(flag, 13), 4), "JJMN")), b"1"*16, b"1"*16) for flag in step11msg(flag, n)];

def smartPrint(encs):
    ret = ""
    for e in encs:
        ret += e + "\n";
    return ret[:-1]
        
