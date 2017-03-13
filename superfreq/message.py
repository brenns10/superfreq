# -*- coding: utf-8 -*-
"""
Contains the Message and Alphabet classes.
"""
from collections import Counter
import string


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
                offsets.append(i)
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
            if idx < len(offsets) and offsets[idx] == i:
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


UPCASE_ALPHABET = Alphabet(
    string.ascii_uppercase,
    dict(zip(string.ascii_letters, string.ascii_uppercase * 2))
)


class Message(object):
    """Represents a plaintext or ciphertext message.

    Most of the tools in this package are useless without the idea of an
    Alphabet (like uppercase English letters). Also, most messages come with
    punctuation and spacing, which are not part of their "alphabet". This class
    makes it simple to use any alphabet you'd like, and always be able to
    preserve the original spacing and punctuation, even though the
    cryptanalysis may want to get rid of it.

    """

    def __init__(self, text, alphabet=None, is_text=True):
        """Create a new Message instance.

        :param text: iterable of characters, not all of which have to be part
            of the alphabet
        :param alphabet: the alphabet we'll be interpreting the message in. If
            this is none, we use the default (English uppercase)
        :param is_text: when this is true, convert everything to string before
            printing it out
        """
        self.original = text
        if alphabet is None:
            self.alphabet = UPCASE_ALPHABET
        else:
            self.alphabet = alphabet
        self.is_text = is_text
        self.alphatext, self.offsets = self.alphabet.to_alphabet(text)

    def _get_printable(self, string):
        if self.is_text:
            return ''.join(string)
        else:
            return string

    def __repr__(self):
        base = 'Message(%r' % self.as_original()[:40]
        if self.alphabet is not UPCASE_ALPHABET:
            base += ', %r' % self.alphabet
        if not self.is_text:
            base += ', is_text=False'
        return base + ')'

    def as_original(self):
        """Use the message Alphabet's from_alphabet to make pretty output."""
        return self._get_printable(self.alphabet.from_alphabet(
            self.alphatext, self.offsets, self.original
        ))

    @classmethod
    def create_from(cls, old_message, new_alphatext):
        """Create a new Message from an old one, substituting new alphatext.

        :param old_message: A Message instance
        :param new_alphatext: Alphatext to use in the new instance
        :returns: A new Message instance with same original, but new alpha
        """
        new = cls(old_message.original, old_message.alphabet,
                  old_message.is_text)
        new.alphatext = new_alphatext
        return new
