# -*- coding: utf-8 -*-
"""
Homemade frequency analysis tools.
"""
from collections import Counter
from itertools import cycle, islice
import math
import random
import string

ENGFREQ = {
    'A': 0.08167,
    'B': 0.01492,
    'C': 0.02782,
    'D': 0.04253,
    'E': 0.12702,
    'F': 0.02228,
    'G': 0.02015,
    'H': 0.06094,
    'I': 0.06966,
    'J': 0.00153,
    'K': 0.00772,
    'L': 0.04025,
    'M': 0.02406,
    'N': 0.06749,
    'O': 0.07507,
    'P': 0.01929,
    'Q': 0.00095,
    'R': 0.05987,
    'S': 0.06327,
    'T': 0.09056,
    'U': 0.02758,
    'V': 0.00978,
    'W': 0.02360,
    'X': 0.00150,
    'Y': 0.01974,
    'Z': 0.0007,
}


def roundrobin(*iterables):
    "roundrobin('ABC', 'D', 'EF') --> A D E B F C"
    # Recipe credited to George Sakkis
    pending = len(iterables)
    nexts = cycle(iter(it).__next__ for it in iterables)
    while pending:
        try:
            for next in nexts:
                yield next()
        except StopIteration:
            pending -= 1
            nexts = cycle(islice(nexts, pending))


class Alphabet(object):
    """Alphabet is a class that standardizes behavior for character sets.

    Many example ciphers only use upper-case letters as their alphabet, leaving
    punctuation characters in plaintext. However, you may want to use the
    entire ASCII character set as an alphabet, or the set of letters and
    numbers. Rather than hard-code the alphabet being used, this class allows
    you to create a custom alphabet, and it will implement all the operations
    needed for frequency analysis on it.

    """

    def __init__(self, characters, mapper):
        """Create an alphabet.

        :param characters: A list of the characters in the alphabet. Order does
            matter here! Characters must be hashable (not necessarily strings)
        :param mapper: A dict mapping items from outside of the alphabet into
            it. For instance, with an uppercase letter alphabet, you'd like to
            map lower case letters to upper-case.

        """
        self.characters = list(characters)
        self.charset = set(self.characters)
        self.mapper = mapper

    def to_alphabet(self, original):
        """Applies the mapper to a list of characters.

        For each character, if it exists in the alphabet, it is not modified.
        If it does not exist in the alphabet, we try to map it using the
        mapper. If it does not exist in the mapper, it is silently ignored.

        :param original: iterable of characters
        :returns: a two-tuple:
            [0]: mapped list of characters
            [1]: list of offsets from the original string

        """
        mapped = []
        offsets = []
        for i, character in enumerate(original):
            if character in self.charset:
                mapped.append(character)
                offsets.append(i)
            elif character in self.mapper:
                mapped.append(self.mapper[character])
        return mapped, offsets

    def from_alphabet(self, mapped, offsets, original):
        """Reconstructs something that looks like the original string.

        Since to_alphabet strips out non-alphabet characters (like punctuation
        or spacing), it is convenient to have a way to reverse it. This will
        re-insert those characters back into a string. It will not reverse the
        mapping, because there is no guarantee that the mapping is 1:1.

        :param mapped: an iterable string from this alphabet
        :param offsets: a list of offsets from the original string
        :param original: the original string
        :returns: a list of characters "reconstructed"

        """
        idx = 0
        res = []
        for i, orig in enumerate(original):
            if offsets[idx] == i:
                res.append(mapped[idx])
                idx += 1
            else:
                res.append(orig)
        return res

    def indices(self, string):
        """Given a string, returns a list of their indices in the alphabet."""
        return list(map(self.characters.index, string))

    def chars(self, indices):
        """Given indices, returns a list of characters."""
        return [self.characters[i % len(self.characters)] for i in indices]

    def shift(self, string, offset):
        """Given an alphabet string, shift each character by the given offset.

        :param string: iterable of characters from this alphabet
        :param offset: offset to shift by (positive or negative, any magnitude)
        :returns: list of shifted characters

        """
        indices = self.indices(string)
        indices = [x + offset for x in indices]
        return self.chars(indices)

    def empty_counter(self):
        """Create an empty counter for this alphabet. """
        return Counter({c: 0 for c in self.characters})


DEFAULT = Alphabet(string.ascii_uppercase, dict(zip(string.ascii_letters, string.ascii_uppercase * 2)))


class SimilarityMetric(object):
    """Computes similarity between two frequency distributions.

    In order to determine whether or not a possible decryption is right, you
    could have a human look at it. But that gets really painful really quick.
    A better way is to analyze the frequency of letters and compare it to that
    of normal English. This class implements a similarity metric - cosine
    similarity.

    """

    def __init__(self, alphabet, counter=None, training=None):
        """Create a similarity metric instance for a given alphabet.

        :param alphabet: Alphabet instance to use
        :param counter: Dict mapping characters to counts, from the source
            language. ENGFREQ is one such example.
        :param training: An alphabet string that should be used as a sample.
            Must provide either this or counter.
        """
        self.alphabet = alphabet
        if counter:
            self.counter = counter
        elif training:
            self.counter = self.count(training)
        self.frequencies = self.frequency(self.counter)

    def count(self, string):
        """Return counts for a string."""
        counter = self.alphabet.empty_counter()
        counter.update(string)
        return counter

    def frequency(self, counter):
        """Return frequencies from a count dict."""
        l = sum(counter.values())
        return {k: v/l for k, v in counter.items()}

    def compute(self, string):
        """Compute the similarity metric between the baseline and a string."""
        freq = self.frequency(self.count(string))
        num = 0
        lden = 0
        rden = 0
        for k in self.alphabet.characters:
            num += freq[k] * self.frequencies[k]
            lden += freq[k] ** 2
            rden += self.frequencies[k] ** 2
        return num / (math.sqrt(lden) * math.sqrt(rden))


class CaesarCipher(object):
    """A very simple cipher which shifts each character by a certain amount.

    For example, here it is in action with a shift of 2:

        plaintext:  STEPHEN IS COOL
        ciphertext: UVGRJGP KU EQQN
    """

    def __init__(self, shift, alphabet):
        """A Caesar Cipher's key is just an integer shift."""
        self.shift = shift
        self.alphabet = alphabet

    def encrypt(self, message):
        """Encrypt the message."""
        return self.alphabet.shift(message, self.shift)

    def decrypt(self, message):
        """Reverse of encrypt."""
        return self.alphabet.shift(message, -self.shift)

    @classmethod
    def crack(cls, message, alphabet, sim):
        """Break the Caesar cipher by a frequency analysis.

        Given a message and a similarity metric, try each possible shift and
        return the one that maximizes the similarity metric.

        :param message: ciphertext
        :param alphabet: the alphabet of the message
        :param sim: A SimilarityMetric to use for comparison
        :returns: a three-tuple:
            [0]: similarity metric value
            [1]: decrypted message
            [2]: the cipher instance used to decrypt it
        """
        options = []
        for i in range(len(alphabet.characters)):
            cipher = cls(i, alphabet)
            result = cipher.decrypt(message)
            options.append((sim.compute(result), result, cipher))
        return max(options)


class VigenereCipher(object):
    """A more complex variation on a CaesarCipher.

    This method involves a key word or phrase. This is overlaid on the
    plaintext, and each letter of the key is interpreted as a shift amount. An
    example:

        plaintext:  HELLO ITS ME AGAIN
        key:        WAFFL ESW AF FLESW
        ciphertext: DEQQZ MLO MJ FREAJ

    """

    def __init__(self, alphabet, key=None, indices=None):
        """Create an instance of the VigenereCipher

        :param alphabet: Alphabet instance to use.
        :param key: a key word to use
        :param indices: a list of indices to use instead
        """
        if indices:
            self.indices = indices
            self.key = alphabet.chars(indices)
        elif key:
            self.indices = alphabet.indices(key)
            self.key = key
        self.negative_indices = [-x for x in self.indices]
        self.alphabet = alphabet

    def _split_shift_join(self, message, indices):
        L = len(indices)
        submessages = [message[i::L] for i in range(L)]
        shifted = [self.alphabet.shift(sub, shift)
                   for sub, shift in zip(submessages, indices)]
        return roundrobin(*shifted)

    def encrypt(self, message):
        return self._split_shift_join(message, self.indices)

    def decrypt(self, message):
        return self._split_shift_join(message, self.negative_indices)


def main():
    import sys
    print('Reading plaintext from %s' % sys.argv[1])
    with open(sys.argv[1], 'r') as f:
        plaintext = f.read()
    alpha_plaintext, offsets = DEFAULT.to_alphabet(plaintext)
    print('Plaintext starts like this:')
    print('%s...' % ''.join(alpha_plaintext[:77]))
    key = random.randint(1, 25)
    print('Encrypting with CaesarCipher(%d)' % key)
    cipher = CaesarCipher(key, DEFAULT)
    ciphertext = cipher.encrypt(alpha_plaintext)
    print('Ciphertext starts like this:')
    print('%s...' % ''.join(ciphertext[:77]))
    print('Cracking...')
    sim = SimilarityMetric(DEFAULT, counter=ENGFREQ)
    corr, decrypted, cipher = CaesarCipher.crack(ciphertext, DEFAULT, sim)
    print('Best result, score %f, is CasearCipher(%d)' % (corr, cipher.shift))
    print('Decrypted text starts like this:')
    print('%s...' % ''.join(decrypted[:77]))


if __name__ == '__main__':
    main()
