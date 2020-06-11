"""Used for:
- Scanning bookmarks to open them all, for testing.
- When printing, gets descriptions associated to URLs.
"""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__ = "GPL"

################################################################################

# Yields tuples of the form ( list(symbol), times), and repetition
# are detected over contiguous sequences of identical symbols.
# Symbols can be of any type except tuple and list.
def __squeeze_events_one(symbols_iterator):
    try:
        last_read_symbol = next(symbols_iterator)
    except StopIteration:
        return
    times_num = 1
    for one_symbol in symbols_iterator:
        if one_symbol == last_read_symbol:
            times_num += 1
        else:
            yield [last_read_symbol, ], times_num
            last_read_symbol = one_symbol
            times_num = 1
    yield [last_read_symbol, ], times_num


def __squeeze_events_multi_aux(symbols_iterator, max_len):
    if max_len == 1:
        symbols_iterator_next = __squeeze_events_one(symbols_iterator)
    else:
        iter_previous = __squeeze_events_multi_aux(symbols_iterator, max_len-1)
        symbols_iterator_next = __squeeze_events_fixed(iter_previous, max_len)
    for symbol_and_times in symbols_iterator_next:
        yield symbol_and_times


# Detects repetition of sub-sequences of up to max_len length.
def __squeeze_events_fixed(symbols_iterator, max_len):
    read_array_position = 0
    read_array_size = max_len * 2
    read_array = [None] * read_array_size
    for symbol_and_times in symbols_iterator:
        read_array[read_array_position] = symbol_and_times
        read_array_position += 1
        if read_array_position == read_array_size: break
    else:
        for sub_array_position in range(read_array_position):
            yield [read_array[sub_array_position], ], 1
        return

    times_num = 1
    while True:
        if read_array[:max_len] == read_array[max_len:]:
            sub_position = max_len
            times_num += 1
            for symbol_and_times in symbols_iterator:
                read_array[sub_position] = symbol_and_times
                sub_position += 1
                if sub_position == read_array_size: break
            else:
                yield read_array[:max_len], times_num
                for array_element in read_array[max_len: sub_position]:
                    yield [array_element, ], 1
                break
        elif times_num > 1:
            yield read_array[:max_len], times_num
            read_array[:max_len] = read_array[max_len:]
            times_num = 1
            sub_position = max_len
            for symbol_and_times in symbols_iterator:
                read_array[sub_position] = symbol_and_times
                sub_position += 1
                if sub_position == read_array_size: break
            else:
                for array_element in read_array[:sub_position]:
                    yield [array_element, ], 1
                break
        else:
            yield [read_array[0]], 1
            read_array[:-1] = read_array[1:]
            try:
                read_array[-1] = next(symbols_iterator)
            except StopIteration:
                for array_element in read_array[: -1]:
                    yield [array_element, ], 1
                break


def squeeze_events_sequence(input_events_sequence, max_len):
    symbols_iterator = iter(input_events_sequence)
    symbols_iterator_next = __squeeze_events_multi_aux(symbols_iterator, max_len)
    for symbol_and_times in symbols_iterator_next:
        yield symbol_and_times

# This is for testing purpose, to ensure that a squeezed list of function calls can be fully restored.
def inflate_squeezed_sequence(squeezed_sequence):
    for symbol_and_times in squeezed_sequence:
        if isinstance(symbol_and_times, tuple):
            sym_sequence, sym_times = symbol_and_times
            iter_inflated_sequence = inflate_squeezed_sequence(sym_sequence)
            if sym_times == 1:
                for sub_symbol_and_times in iter_inflated_sequence:
                    yield sub_symbol_and_times
            else:
                list_inflated_sequence = list(iter_inflated_sequence)
                for ix in range(sym_times):
                    for sub_symbol_and_times in list_inflated_sequence:
                        yield sub_symbol_and_times
        else:
            yield symbol_and_times

# This simplifies a squeeze sequences becquse it cqn be too complicated for no reasons,
# except showing how the compression worked.
def simplify_squeezed_sequence(squeezed_sequence):
    for symbol_and_times in squeezed_sequence:
        if isinstance(symbol_and_times, tuple):
            sym_sequence, sym_times = symbol_and_times
            iter_inflated_sequence = inflate_squeezed_sequence(sym_sequence)
            if sym_times == 1:
                for sub_symbol_and_times in iter_inflated_sequence:
                    yield sub_symbol_and_times
            else:
                yield symbol_and_times
        else:
            yield symbol_and_times
