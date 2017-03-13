# -*- coding: utf-8 -*-
"""
Run the superfreq main program.

"""
import random

from superfreq.cipher import CaesarCipher
from superfreq.message import Message
from superfreq.util import SimilarityMetric, ENGFREQ


def main():
    import sys
    with open(sys.argv[1], 'r') as f:
        plaintext = f.read()
    pt_message = Message(plaintext)
    print('Plaintext:')
    print(pt_message)
    cipher = CaesarCipher(random.randint(1, 25))
    print('Encrypting with %r' % cipher)
    ciphertext = cipher.encrypt(pt_message)
    print('Ciphertext:')
    print(ciphertext)
    print('Cracking...')
    sim = SimilarityMetric(counter=ENGFREQ)
    corr, decrypted, cipher = list(CaesarCipher.crack(ciphertext, sim))[0]
    print('Best result, score %f, is %r' % (corr, cipher))
    print('Decrypted text:')
    print(decrypted)


main()
