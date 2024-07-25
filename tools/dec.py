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



def step1r():
    pass

def step2r(s, key):
    return Caesar(key=key).decipher(s, keep_punct=True).lower();

def step3r(s, key):
    return Railfence(key).decipher(s, keep_punct=True).lower();
    
def step4r(s, key):
    ans = b"";
    s = s.upper().encode("utf");
    key = key.upper().encode("utf");
    for a, b in zip(s, itertools.cycle(key)):
        if not a in alphabet:
            ans += p8(a);
        else:
            val1 = a - 65;
            val2 = b - 65;
            ans += p8((((val1 - val2) + 26*10) % 26) + 65);
    return ans.decode("utf").lower();

def step5r(s):
    en = Enigma(
        settings=("J", "A", "Y"),
        ringstellung=("D", "E", "N")
    );
    ans = "";
    for char in s:
        if char in ascii_letters:
            ans += en.decipher(char);
        else:
            ans += char;
    return ans.lower();    

def step6r(s, key, iv):
    b = bytes.fromhex(s);
    aes = AES.new(key, AES.MODE_CBC, iv=iv);
    decrypted = unpad(aes.decrypt(b), 16); 
    return decrypted.decode("utf");

def step7r(s):
    ans = "";    
    return "".join([u10_TO_MORSE[char] for char in s.split()]).lower();

def step8r(s, l, r):   
    while s.find(".") != -1:
        s = s[:s.find(".")-l] + " " + s[s.find(".")+r+1:];    
    return s;

def decryption(flags):
    dec = [step2r(step3r(step4r(step5r(step6r(step7r(step8r(flag, 5, 5)), b"1"*16, b"1"*16)), "JJMN"), 4), 13) for flag in flags]; 
    return dec[int((dec[-1] if dec[-1].find("-") == -1 else dec[-1][:dec[-1].find("-")]))-1];

def smartUndoPrint(s):
    return s.split("\n");
        
