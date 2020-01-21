#!/usr/bin/env python

"""Tests the ability to detect repetieion in sequences of symbols.
This is designed for sequences of system calls.
"""

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__ = "GPL"




import cgitb
import cgi
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



class SplitExecutionStreamsTest(unittest.TestCase):
    """When parsing a strace log, there are several threads or processes all mixed together.
    dockit splits them and processes them individually, to detect the resources used by each process.
    This test use this feature and separate the flow of instructions into several distinct streams.
    The intention is to detect repetition of similar sequences of functions calls."""
    class Iterator:
        def __init__(self):
            print("Iterator.__init__")

        def __iter__(self):
            print("Iterator.__iter__")
            print("Before yield from")
            x = yield
            print("Before yield to")
            yield x
            # raise StopIteration

    class FunctionCallsQueue:
        def __init__(self, thread_identifier):
            self._thread_identifier = thread_identifier
            self._iterator = SplitExecutionStreamsTest.Iterator()

            def processing_function():
                print("In processing_function")
                lib_calls_sequences.squeeze_events_sequence(self._iterator, max_len=5)

            self._processing_function = processing_function()
            self.toto = self._iterator.__iter__()
            next(self.toto)
            #next(self._processing_function)

        def push_function_name(self, function_name):
            print("push_function_name function_name=", function_name)
            self.toto.send(function_name)
            #self._processing_function.send(function_name)

    @unittest.skip("Not Implemented yet")
    def test_split_stream(self):
        dict_pids = {}

        def batch_callback(one_batch):
            aCore = one_batch.m_core

            aPid = aCore.m_pid
            print("aPid=", aPid)
            print("aCore=", aCore.GetFunction())

            try:
                function_calls_queue = dict_pids[aPid]
            except KeyError:
                # This is the first system call of this process.
                function_calls_queue = SplitExecutionStreamsTest.FunctionCallsQueue(aPid)
                dict_pids[aPid] = function_calls_queue

            function_calls_queue.push_function_name(aCore.GetFunction())

        dockit.ParseInstructionsStream(
            inputLogFile=path_prefix_input_file("sample_shell.ltrace.log"),
            withWarning = True,
            tracer="ltrace",
            topPid=0,
            verbose=True,
            batch_callback = batch_callback)

