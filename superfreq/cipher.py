# -*- coding: utf-8 -*-
"""
Ciphers for superfreq!

Ciphers should behave as follows:
- Their constructor arguments should be keys.
- encrypt() should take a message object and return an encrypted Message
- decrypt() should take a message object and return a decrypted Message
- decrypt(encrypt(original)) == original
- Class method crack() takes a message and a similarity metric, and it is a
  generator of the following tuples, in roughly decreasing probability
  (similarity, message, cipher)
"""
from collections import Counter
import re

from superfreq.message import Message
from superfreq.util import factors, index_of_coincidence, roundrobin


class CaesarCipher(object):
    """A very simple cipher which shifts each character by a certain amount.

    For example, here it is in action with a shift of 2:

        plaintext:  STEPHEN IS COOL
        ciphertext: UVGRJGP KU EQQN
    """

    def __init__(self, shift):
        """A Caesar Cipher's key is just an integer shift."""
        self.shift = shift

    def __repr__(self):
        return 'CaesarCipher(%r)' % self.shift

    def encrypt(self, message):
        """Encrypt the message."""
        return Message.create_from(
            message, message.alphabet.shift(message.alphatext, self.shift),
        )

    def decrypt(self, message):
        """Reverse of encrypt."""
        return Message.create_from(
            message, message.alphabet.shift(message.alphatext, -self.shift),
        )

    @classmethod
    def crack(cls, message, sim):
        """Break the Caesar cipher by a frequency analysis.

        Given a message and a similarity metric, try each possible shift and
        return the one that maximizes the similarity metric.

        :param message: ciphertext in a Message object
        :param sim: A SimilarityMetric to use for comparison
        :returns: a three-tuple:
            [0]: similarity metric value
            [1]: decrypted message
            [2]: the cipher instance used to decrypt it
        """
        options = []
        for i in range(len(message.alphabet.characters)):
            cipher = cls(i)
            result = cipher.decrypt(message)
            options.append((sim.compute(result), result, cipher))
        options.sort(reverse=True)
        return options


class VigenereCipher(object):
    """A more complex variation on a CaesarCipher.

    This method involves a key word or phrase. This is overlaid on the
    plaintext, and each letter of the key is interpreted as a shift amount. An
    example:

        plaintext:  HELLO ITS ME AGAIN
        key:        WAFFL ESW AF FLESW
        ciphertext: DEQQZ MLO MJ FREAJ

    """

    def __init__(self, key):
        """Create an instance of the VigenereCipher

        :param key: a key word to use
        """
        self.key = key

    def __repr__(self):
        return 'VigenereCipher(%r)' % self.key

    def _split_shift_join(self, message, indices):
        L = len(indices)
        submessages = [message.alphatext[i::L] for i in range(L)]
        shifted = [message.alphabet.shift(sub, shift)
                   for sub, shift in zip(submessages, indices)]
        return Message.create_from(
            message, list(roundrobin(*shifted)),
        )

    def encrypt(self, message):
        indices = message.alphabet.indices(self.key)
        return self._split_shift_join(message, indices)

    def decrypt(self, message):
        indices = message.alphabet.indices(self.key)
        negatives = [-x for x in indices]
        return self._split_shift_join(message, negatives)

    @classmethod
    def kasiski(cls, message):
        s = ''.join(message.alphatext)
        matches = re.findall(r'(.{2,}).+\1', s)
        factor_counts = Counter()
        for m in matches:
            first_idx = s.index(m)
            second_idx = s.index(m, first_idx + 1)
            factor_counts.update(factors(second_idx - first_idx))
            print(second_idx - first_idx)
        print(factor_counts)

    @classmethod
    def ic(cls, message):
        s = ''.join(message.alphatext)
        for i in range(2, len(s)-1):
            iocs = [index_of_coincidence(s[x::i]) * 26 for x in range(i)]
            print('For key size %d: %f' % (i, sum(iocs)/i))


    @classmethod
    def crack(cls, message, sim):
        """Try to crack the Vigenere Cipher.

        This will employ a Kasiski examination to determine a list of possible
        key lengths. Then, it will attempt to crack the individual Caesar
        Ciphers that make up the message.

        """
        cls.kasiski(message)
        cls.ic(message)
