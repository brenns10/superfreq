[superfreq](https://www.youtube.com/watch?v=QYHxGBH6o4M)
=========

This is a frequency analysis tool I'm working on, in the hopes of being able to
automatically crack some of the simpler ciphers out there. Nothing
groundbreaking or complex, but rather just a fun project.

Currently, you can use it (with Python 3) as follows:

    python -m superfreq README.md
    
This will read this file as plaintext, apply a Caesar cipher, and then use its
"crack" functionality to determine the key and print the original text. It's
kind of like picking your own card out of a deck, but hey, you gotta start
somewhere, right?
