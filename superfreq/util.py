# -*- coding: utf-8 -*-
"""
Utility functions for frequency analysis.
"""
from collections import Counter
from itertools import cycle, islice
from functools import reduce
import math

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


def factors(n):
    return set(reduce(list.__add__,
                ([i, n//i] for i in range(1, int(n**0.5) + 1) if n % i == 0)))


def index_of_coincidence(s):
    """Return the index of coincidence of a string."""
    c = Counter(s)
    x = 0
    for _, n in c.items():
        x += n * (n - 1)
    N = len(s)
    return x / (N * (N - 1))


class SimilarityMetric(object):
    """Computes similarity between two frequency distributions.

    In order to determine whether or not a possible decryption is right, you
    could have a human look at it. But that gets really painful really quick.
    A better way is to analyze the frequency of letters and compare it to that
    of normal English. This class implements a similarity metric - cosine
    similarity.

    """

    def __init__(self, counter=None, training=None):
        """Create a similarity metric instance.

        :param counter: Dict mapping characters to counts, from the source
            language. ENGFREQ is one such example.
        :param training: A Message that will be used as training for the
            language. Must provide either this or counter.
        """
        if counter:
            self.counter = counter  # hopefully matches message alphabet
        elif training:
            self.counter = self.count(training)
        self.frequencies = self.frequency(self.counter)

    def count(self, message):
        """Return counts for a string."""
        counter = message.alphabet.empty_counter()
        counter.update(message.alphatext)
        return counter

    def frequency(self, counter):
        """Return frequencies from a count dict."""
        l = sum(counter.values())
        return {k: v/l for k, v in counter.items()}

    def compute(self, message):
        """Compute the similarity metric between the baseline and a string."""
        freq = self.frequency(self.count(message))
        num = 0
        lden = 0
        rden = 0
        for k in message.alphabet.characters:
            num += freq[k] * self.frequencies[k]
            lden += freq[k] ** 2
            rden += self.frequencies[k] ** 2
        return num / (math.sqrt(lden) * math.sqrt(rden))
