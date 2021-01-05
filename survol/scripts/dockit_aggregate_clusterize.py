# This optional module aggregates function calls into bigger sequences.
# It is not necessary for Docker files.
# All functions calls and all objects are processed identically.
# It just detects repetitions of identical parameters.

import sys
import datetime

# TODO: It should not depend on this package.
if __name__ == '__main__':
    import linux_api_definitions
else:
    from . import linux_api_definitions


def _signature_for_repetitions(batch_range):
    return "+".join([a_btch.get_signature_with_args() for a_btch in batch_range])


class BatchLetSequence(linux_api_definitions.BatchLetBase, object):
    """
    This groups several contiguous BatchLet which form a logical operation.
    For example (If the argument is factorised).:
      Read(x)
      Write(x)

    ... or ...
      fseek("dummy.txt")
      fwrite("dummy.txt")

    There can be several way to "reuse" a sequence, depending on other similar sequences.
    """
    def __init__(self, arr_batch, style):
        batch_core = linux_api_definitions.BatchLetCore()

        # TODO: Instead of a string, this could be a tuple because it is hashable.
        concat_signs = "+".join([btch.get_signature_without_args() for btch in arr_batch])
        batch_core._function_name = "(" + concat_signs + ")"

        batch_core.m_status = linux_api_definitions.BatchStatus.sequence

        # This is returned by the method get_significant_args()

        # Cannot use a set because lists are not hashable, and objects always different.
        # Because there are very few arguments, it is allright to iterate on each list.
        args_array = []
        for btch in arr_batch:
            for one_arg in btch.get_significant_args():
                if not one_arg in args_array:
                    args_array.append(one_arg)
        batch_core.m_parsedArgs = args_array

        # All batchlets should have the same pid.
        batch_core.m_pid = arr_batch[0].m_core.m_pid

        batch_core._time_start = arr_batch[0].m_core._time_start
        batch_core._time_end = arr_batch[-1].m_core._time_end

        def exec_time_delta(time_end, time_start):
            """
            This is equivalent to this, but faster because locales are not used:
                def str_to_date_time(the_time):
                    return datetime.datetime.strptime(the_time, '%H:%M:%S.%f')

                return (str_to_date_time(time_end) - str_to_date_time(time_start)).total_seconds()
            """
            split_end = time_end.split(":")
            split_start = time_end.split(":")
            time_delta = 3600 * (int(split_end[0]) - int(split_start[0])) \
                         + 60 * (int(split_end[1]) - int(split_start[1])) \
                         + float(split_end[2]) - float(split_start[2])
            return time_delta

        batch_core.m_execTim = exec_time_delta(batch_core._time_end, batch_core._time_start)

        super(BatchLetSequence, self).__init__(batch_core,style)


class BatchFlow:
    """This is an execution flow, associated to a process. And a thread ?"""

    def __init__(self):

        self.m_listBatchLets = []
        self.m_coroutine = self.__adding_coroutine()
        next(self.m_coroutine)

    def append_batch_to_flow(self, btchLet):
        """It processes system calls on-the-fly without intermediate storage."""
        self.m_coroutine.send(btchLet)

    def __adding_coroutine(self):
        lst_batch = None
        while True:
            btch_let = yield

            if lst_batch and lst_batch.is_same_call(btch_let):
                # This is a compression: Similar and consecutive calls are stored once only.
                lst_batch.m_occurrences += 1
            else:
                self.m_listBatchLets.append(btch_let)
            # Intentionally points to the object actually stored in the container,
            # instead of the possibly transient object returned by yield.
            lst_batch = self.m_listBatchLets[-1]

    def __filter_matched_batches(self):
        """This removes matched batches (Formerly unfinished calls which were matched to the resumed part)
        when the merged batches (The resumed calls) comes immediately after."""
        len_batch = len(self.m_listBatchLets)

        num_subst = 0
        idx_batch = 1
        while idx_batch < len_batch:
            batch_seq = self.m_listBatchLets[idx_batch]
            batch_seq_prev = self.m_listBatchLets[idx_batch - 1]

            # Sanity check.
            if batch_seq_prev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
                    and batch_seq.m_core.m_status == linux_api_definitions.BatchStatus.merged:
                if batch_seq_prev.m_core._function_name != batch_seq.m_core._function_name:
                    raise Exception(
                        "INCONSISTENCY1 %s %s\n" % (
                            batch_seq.m_core._function_name,
                            batch_seq_prev.m_core._function_name))

            if batch_seq_prev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
                    and batch_seq.m_core.m_status == linux_api_definitions.BatchStatus.merged:
                if batch_seq_prev.m_core.m_resumedBatch.m_unfinishedBatch != batch_seq_prev.m_core:
                    raise Exception("INCONSISTENCY2 %s\n" % batch_seq_prev.m_core._function_name)

            if batch_seq_prev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
                    and batch_seq.m_core.m_status == linux_api_definitions.BatchStatus.merged:
                if batch_seq.m_core.m_unfinishedBatch.m_resumedBatch != batch_seq.m_core:
                    raise Exception("INCONSISTENCY3 %s\n" % batch_seq.m_core._function_name)

            if batch_seq_prev.m_core.m_status == linux_api_definitions.BatchStatus.matched \
                    and batch_seq.m_core.m_status == linux_api_definitions.BatchStatus.merged \
                    and batch_seq_prev.m_core.m_resumedBatch == batch_seq.m_core \
                    and batch_seq.m_core.m_unfinishedBatch == batch_seq_prev.m_core:
                del self.m_listBatchLets[idx_batch - 1]
                batch_seq.m_core.m_unfinishedBatch = None
                len_batch -= 1
                num_subst += 1

            idx_batch += 1

        return num_subst

    def __statistics_bigrams(self):
        """
        This counts the frequency of consecutive pairs of calls.
        Used to replace these common pairs by an aggregate call.
        See https://en.wikipedia.org/wiki/N-gram about bigrams.
        About statistics: https://books.google.com/ngrams/info
        """
        len_batch = len(self.m_listBatchLets)

        map_occurences = {}

        idx_batch = 0
        max_idx = len_batch - 1
        while idx_batch < max_idx:
            batch_range = self.m_listBatchLets[idx_batch: idx_batch + 2]
            key_range = _signature_for_repetitions(batch_range)

            try:
                map_occurences[key_range] += 1
            except KeyError:
                map_occurences[key_range] = 1
            idx_batch += 1

        return map_occurences

    def __clusterize_bigrams(self):
        """This examines pairs of consecutive calls with their arguments, and if a pair
        occurs often enough, it is replaced by a single BatchLetSequence which represents it."""
        len_batch = len(self.m_listBatchLets)

        map_occurences = self.__statistics_bigrams()

        num_subst = 0
        idx_batch = 0
        max_idx = len_batch - 1
        batch_seq_prev = None
        while idx_batch < max_idx:
            batch_range = self.m_listBatchLets[idx_batch: idx_batch + 2]
            key_range = _signature_for_repetitions(batch_range)
            num_occur = map_occurences.get(key_range, 0)

            # Five occurences for example, as representative of a repetition.
            if num_occur > 5:
                batch_sequence = BatchLetSequence(batch_range, "Rept")

                # Maybe it is the same as the previous element, if this is a periodic pattern.
                if batch_seq_prev and batch_sequence.is_same_call(batch_seq_prev):
                    # Simply reuse the previous batch.
                    batch_seq_prev.m_occurrences += 1
                    del self.m_listBatchLets[idx_batch: idx_batch + 2]
                    max_idx -= 2
                else:
                    self.m_listBatchLets[idx_batch: idx_batch + 2] = [batch_sequence]
                    max_idx -= 1
                    batch_seq_prev = batch_sequence
                    idx_batch += 1

                num_subst += 1
            else:
                batch_seq_prev = None
                idx_batch += 1
        return num_subst

    def __clusterize_batches_by_arguments(self):
        """Successive calls which have the same arguments are clusterized into logical entities."""
        len_batch = len(self.m_listBatchLets)

        num_subst = 0
        idx_last = 0
        idx_batch = 1
        while idx_batch <= len_batch:
            if idx_batch < len_batch:
                last_batch = self.m_listBatchLets[idx_last]
                last_args = last_batch.get_significant_args()
                if not last_args:
                    idx_last += 1
                    idx_batch += 1
                    continue

                current_batch = self.m_listBatchLets[idx_batch]

                if current_batch.get_significant_args() == last_args:
                    idx_batch += 1
                    continue

            if idx_batch > idx_last + 1:
                # Clusters should not be too big
                batch_seq = BatchLetSequence(self.m_listBatchLets[idx_last: idx_batch], "Args")
                self.m_listBatchLets[idx_last: idx_batch] = [batch_seq]

                len_batch -= (idx_batch - idx_last - 1)
                num_subst += 1

            idx_last += 1
            idx_batch = idx_last + 1
        return num_subst

    def __dump_flow_internal(self, batch_dump):
        batch_dump.flow_header()
        for a_btch in self.m_listBatchLets:
            batch_dump.dump_batch_to_stream(a_btch)
        batch_dump.flow_footer()

    def __dump_flow_simple(self, strm, batch_constructor):
        batch_dump = batch_constructor(strm)
        self.__dump_flow_internal(batch_dump)

    def dump_flow_constructor(self, batch_dump, flow_process_id=None):
        self.__dump_flow_internal(batch_dump)

    def factorise_one_flow(self, verbose, batch_constructor):
        if verbose > 1:
            self.__dump_flow_simple(sys.stdout, batch_constructor)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("factorise_one_flow lenBatch=%d\n" % (len(self.m_listBatchLets)))
        num_subst = self.__filter_matched_batches()
        if verbose > 0:
            sys.stdout.write("factorise_one_flow num_subst=%d lenBatch=%d\n"
                             % (num_subst, len(self.m_listBatchLets)))

        idx_loops = 0
        while True:
            if verbose > 1:
                self.__dump_flow_simple(sys.stdout, batch_constructor)

            if verbose > 0:
                sys.stdout.write("\n")
                sys.stdout.write("factorise_one_flow lenBatch=%d\n" % (len(self.m_listBatchLets)))
            num_subst = self.__clusterize_bigrams()
            if verbose > 0:
                sys.stdout.write("factorise_one_flow num_subst=%d lenBatch=%d\n"
                                 % (num_subst, len(self.m_listBatchLets)))
            if num_subst == 0:
                break
            idx_loops += 1

        if verbose > 1: self.__dump_flow_simple(sys.stdout, batch_constructor)

        if verbose > 0:
            sys.stdout.write("\n")
            sys.stdout.write("factorise_one_flow lenBatch=%d\n" % (len(self.m_listBatchLets)))
        num_subst = self.__clusterize_batches_by_arguments()
        if verbose > 0:
            sys.stdout.write(
                "factorise_one_flow num_subst=%d lenBatch=%d\n" % (num_subst, len(self.m_listBatchLets)))

        if verbose > 1: self.__dump_flow_simple(sys.stdout, batch_constructor)

