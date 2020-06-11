#!/usr/bin/env python

"""Tests the ability to detect repetieion in sequences of symbols.
This is designed for sequences of system calls.
"""

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__ = "GPL"


import os
import re
import sys
import itertools
import unittest

from init import *

from survol import lib_calls_sequences

class RepetitionDetectionTest(unittest.TestCase):
    """These are unit tests of the capability to squeeze a sequence of system calls.
    The idea is to detect repetition of the same sequence of system calls.
    When a specific sequence of calls is repeated, it assumes a specific processing or function.
    """
    def aux_restore(self, max_size, list_input):
        iter_output = lib_calls_sequences.squeeze_events_sequence(list_input, max_size)
        list_output = list(iter_output)
        iter_inflate = lib_calls_sequences.inflate_squeezed_sequence(list_output)
        list_inflate = list(iter_inflate)
        print("list_output=", list_output)
        self.assertTrue(list_inflate == list_input)

    def aux_squeeze(self, max_size, list_input, list_expected):
        iter_output = lib_calls_sequences.squeeze_events_sequence(list_input, max_size)
        list_output = list(iter_output)
        print("list_input=", list_input)
        print("list_expected=", list_expected)
        print("list_output=", list_output)
        self.assertTrue(list_output == list_expected)

    def aux_simplify(self, list_simplified_expected, list_squeezed):
        iter_simplified_actual = lib_calls_sequences.simplify_squeezed_sequence(list_squeezed)
        list_simplified_actual = list(iter_simplified_actual)
        print("list_squeezed=", list_squeezed)
        print("list_simplified_actual=", list_simplified_actual)
        print("list_simplified_expected=", list_simplified_expected)
        self.assertTrue(list_simplified_actual == list_simplified_expected)

    def test_squeeze(self):
        self.aux_squeeze(5, [1], [([([([([([1], 1)], 1)], 1)], 1)], 1)])
        self.aux_squeeze(2, [1, 2], [([([1], 1)], 1), ([([2], 1)], 1)])
        self.aux_squeeze(2, [1, 2, 3], [([([1], 1)], 1), ([([2], 1)], 1), ([([3], 1)], 1)])
        self.aux_squeeze(2, [1, 1, 1], [([([1], 3)], 1)])
        self.aux_squeeze(3, [1, 1], [([([([1], 2)], 1)], 1)])
        self.aux_squeeze(3, ['1', '1', '1'], [([([(['1'], 3)], 1)], 1)])
        self.aux_squeeze(3, [1, 1, 1], [([([([1], 3)], 1)], 1)])
        self.aux_squeeze(3, [1, 2, 3], [([([([1], 1)], 1)], 1), ([([([2], 1)], 1)], 1), ([([([3], 1)], 1)], 1)])
        self.aux_squeeze(3, ['1', '2', '3', '4'], [([([(['1'], 1)], 1)], 1), ([([(['2'], 1)], 1)], 1), ([([(['3'], 1)], 1)], 1), ([([(['4'], 1)], 1)], 1)])
        self.aux_squeeze(3, [1, 2, 3, 4, 5, 6], [([([([1], 1)], 1)], 1), ([([([2], 1)], 1)], 1), ([([([3], 1)], 1)], 1), ([([([4], 1)], 1)], 1), ([([([5], 1)], 1)], 1), ([([([6], 1)], 1)], 1)])
        self.aux_squeeze(3, [1, 2, 3, 1, 2, 3], [([([([1], 1)], 1), ([([2], 1)], 1), ([([3], 1)], 1)], 2)])

    def test_restore(self):
        self.aux_restore(6, [1, 2, 3, 4, 5,1, 2, 3, 4, 5,1, 2, 3, 4, 5,1, 2, 3, 4, 5,1, 2, 3, 4, 5, 6])

    def test_restore_combinations(self):
        for max_len in [3, 7]:
            for one_input_list in itertools.combinations_with_replacement(['a', 'b', 'c', 'd'], 8):
                self.aux_restore(max_len, list(one_input_list))


    def test_simplify(self):
        self.aux_simplify([1], [([([([([([1], 1)], 1)], 1)], 1)], 1)])
        self.aux_simplify([1, 2], [([([1], 1)], 1), ([([2], 1)], 1)])



