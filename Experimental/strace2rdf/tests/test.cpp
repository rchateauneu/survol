// Must come before the rest.
#include "pch.h"

import straceparser;
import std;


using namespace std;

TEST(TestCaseName, TestName) {
  EXPECT_EQ(1, 1);
  EXPECT_TRUE(true);
}

TEST(TestParseStrace, ParseFileCtor) {
	const string filename = R"(C:\Users\rchat\Developpement\STraceToRdf\strace2rdf\TestData\bash_fedora.strace.4233.log)";

	STraceParser parser(filename);
}

TEST(TestParseStrace, ParseFileLoop) {
	const string filename = R"(C:\Users\rchat\Developpement\STraceToRdf\strace2rdf\TestData\bash_fedora.strace.4233.log)";

	STraceParser parser(filename);
	for (;;) {
		const auto& [tripleStoreStatus, triplestoreRef] = parser.get_next_triplestore();
		if (tripleStoreStatus == Line::LineState::EndOfFile) {
			break;
		}
		switch (tripleStoreStatus) {
		case Line::LineState::Unsupported:
			continue;
		case Line::LineState::Normal:
			triplestoreRef.display();
			break;
		case Line::LineState::Resumed:
			continue;
		default:
			throw runtime_error("Invalid code");
		}
	}
}

TEST(TestParseLine, WithoutPidCloneNormal) {
	const char* input = "19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "clone");
	EXPECT_EQ(line.pid(), Line::no_pid);
	EXPECT_EQ(line.return_value(), "5557");
	EXPECT_EQ(line.execution_time(), 0.000185);
	EXPECT_EQ(line.time_as_string(), "19:58:35.830990000");
	EXPECT_EQ(line.args_string(), "child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0");
	EXPECT_EQ(line.args_count(), 3);
	EXPECT_EQ(line.arg_single(0), "child_stack=0");
	EXPECT_EQ(line.arg_single(1), "flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD");
	EXPECT_EQ(line.arg_single(2), "child_tidptr=0x7f3b1ca779d0");
}

TEST(TestParseLine, WithoutOpenErrNormal) {
	const char* input = R"(08:53:31.300577 open("/usr/share/locale/en_GB.UTF-8/LC_MESSAGES/gcc.mo", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000010>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "open");
	EXPECT_EQ(line.pid(), Line::no_pid);
	EXPECT_EQ(line.return_value(), "-1 ENOENT (No such file or directory)");
	EXPECT_EQ(line.execution_time(), 0.00001);
	EXPECT_EQ(line.time_as_string(), "08:53:31.300577000");
	EXPECT_EQ(line.args_string(), R"("/usr/share/locale/en_GB.UTF-8/LC_MESSAGES/gcc.mo", O_RDONLY)");
	EXPECT_EQ(line.args_count(), 2);
	EXPECT_EQ(line.arg_single(0), R"("/usr/share/locale/en_GB.UTF-8/LC_MESSAGES/gcc.mo")");
	EXPECT_EQ(line.arg_single(1), "O_RDONLY");
}

TEST(TestParseLine, WithoutPidPipeNormal) {
	const char* input = "19:58:35.830922 pipe([3<pipe:[52233]>, 4<pipe:[52233]>]) = 0 <0.000016>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "pipe");
	EXPECT_EQ(line.pid(), Line::no_pid);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000016);
	EXPECT_EQ(line.time_as_string(), "19:58:35.830922000");
	EXPECT_EQ(line.args_string(), "[3<pipe:[52233]>, 4<pipe:[52233]>]");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "[3<pipe:[52233]>, 4<pipe:[52233]>]");
}

TEST(TestParseLine, WithoutPidCloneUnfinished) {
	const char* input = "19:58:40.704988 clone( <unfinished ...>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "clone");
	EXPECT_EQ(line.pid(), Line::no_pid);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), 0.0);
	EXPECT_EQ(line.time_as_string(), "19:58:40.704988000");
	EXPECT_EQ(line.args_string(), "");
	EXPECT_EQ(line.args_count(), 0);
}

TEST(TestParseLine, WithoutPidWait4Normal) {
	const char* input = "08:14:35.655748 wait4(-1, 0x7ffcb3e99310, WNOHANG|WSTOPPED|WCONTINUED, NULL) = -1 ECHILD (No child processes) <0.000012>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "wait4");
	EXPECT_EQ(line.pid(), Line::no_pid);
	EXPECT_EQ(line.return_value(), "-1 ECHILD (No child processes)");
	EXPECT_EQ(line.execution_time(), 0.000012);
	EXPECT_EQ(line.time_as_string(), "08:14:35.655748000");
	EXPECT_EQ(line.args_string(), "-1, 0x7ffcb3e99310, WNOHANG|WSTOPPED|WCONTINUED, NULL");
	EXPECT_EQ(line.args_count(), 4);
	EXPECT_EQ(line.arg_single(0), "-1");
	EXPECT_EQ(line.arg_single(1), "0x7ffcb3e99310");
	EXPECT_EQ(line.arg_single(2), "WNOHANG|WSTOPPED|WCONTINUED");
	EXPECT_EQ(line.arg_single(3), "NULL");
}

TEST(TestParseLine, WithoutPidWait4Resumed) {
	const char* input = "08:14:22.592112 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL) = 27127 <1.002478>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "wait4");
	EXPECT_EQ(line.pid(), Line::no_pid);
	EXPECT_EQ(line.return_value(), "27127");
	EXPECT_EQ(line.execution_time(), 1.002478);
	EXPECT_EQ(line.time_as_string(), "08:14:22.592112000");
	EXPECT_EQ(line.args_string(), "[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED|WCONTINUED, NULL");
	EXPECT_EQ(line.args_count(), 3);
	EXPECT_EQ(line.arg_single(0), "[{WIFEXITED(s) && WEXITSTATUS(s) == 0}]");
	EXPECT_EQ(line.arg_single(1), "WSTOPPED|WCONTINUED");
	EXPECT_EQ(line.arg_single(2), "NULL");
}

TEST(TestParseLine, WithPidCloseNormal) {
	const char* input = "[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "close");
	EXPECT_EQ(line.pid(), 4233);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000016);
	EXPECT_EQ(line.time_as_string(), "19:58:35.831382000");
	EXPECT_EQ(line.args_string(), "3<pipe:[52233]>");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "3<pipe:[52233]>");
}

TEST(TestParseLine, WithPidExecveNormal) {
	const char* input = R"([pid  5557] 19:58:35.832440 execve("/usr/bin/ls", ["ls", "--color=auto"], [/* 36 vars */]) = 0 <0.000333>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "execve");
	EXPECT_EQ(line.pid(), 5557);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000333);
	EXPECT_EQ(line.time_as_string(), "19:58:35.832440000");
	EXPECT_EQ(line.args_string(), R"("/usr/bin/ls", ["ls", "--color=auto"], [/* 36 vars */])");
	EXPECT_EQ(line.args_count(), 3);
	EXPECT_EQ(line.arg_single(0), R"("/usr/bin/ls")");
	EXPECT_EQ(line.arg_single(1), R"(["ls", "--color=auto"])");
	EXPECT_EQ(line.arg_single(2), "[/* 36 vars */]");
}

TEST(TestParseLine, WithPidBrkNormal) {
	const char* input = R"([pid  5557] 19:58:35.832893 brk(NULL)   = 0x196e000 <0.000011>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "brk");
	EXPECT_EQ(line.pid(), 5557);
	EXPECT_EQ(line.return_value(), "0x196e000");
	EXPECT_EQ(line.execution_time(), 0.000011);
	EXPECT_EQ(line.time_as_string(), "19:58:35.832893000");
	EXPECT_EQ(line.args_string(), R"(NULL)");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "NULL");
}

TEST(TestParseLine, WithPidMmapNormal) {
	const char* input = R"([pid  5557] 19:58:35.832952 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fb6a4537000 <0.000015>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "mmap");
	EXPECT_EQ(line.pid(), 5557);
	EXPECT_EQ(line.return_value(), "0x7fb6a4537000");
	EXPECT_EQ(line.execution_time(), 0.000015);
	EXPECT_EQ(line.time_as_string(), "19:58:35.832952000");
	EXPECT_EQ(line.args_string(), R"(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)");
	EXPECT_EQ(line.args_count(), 6);
	EXPECT_EQ(line.arg_single(0), "NULL");
	EXPECT_EQ(line.arg_single(1), "4096");
	EXPECT_EQ(line.arg_single(2), "PROT_READ|PROT_WRITE");
	EXPECT_EQ(line.arg_single(3), "MAP_PRIVATE|MAP_ANONYMOUS");
	EXPECT_EQ(line.arg_single(4), "-1");
	EXPECT_EQ(line.arg_single(5), "0");
}

TEST(TestParseLine, WithPidOpenNormal) {
	const char* input = R"([pid  5557] 19:58:35.833033 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000016>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "open");
	EXPECT_EQ(line.pid(), 5557);
	EXPECT_EQ(line.return_value(), "3</etc/ld.so.cache>");
	EXPECT_EQ(line.execution_time(), 0.000016);
	EXPECT_EQ(line.time_as_string(), "19:58:35.833033000");
	EXPECT_EQ(line.args_string(), R"("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC)");
	EXPECT_EQ(line.args_count(), 2);
	EXPECT_EQ(line.arg_single(0), R"("/etc/ld.so.cache")");
	EXPECT_EQ(line.arg_single(1), "O_RDONLY|O_CLOEXEC");
}

TEST(TestParseLine, WithPidFstat) {
	const char* input = R"([pid  5557] 19:58:35.833106 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=124494, ...}) = 0 <0.000012>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "fstat");
	EXPECT_EQ(line.pid(), 5557);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000012);
	EXPECT_EQ(line.time_as_string(), "19:58:35.833106000");
	EXPECT_EQ(line.args_string(), R"(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=124494, ...})");
	EXPECT_EQ(line.args_count(), 2);
	EXPECT_EQ(line.arg_single(0), "3</etc/ld.so.cache>");
	EXPECT_EQ(line.arg_single(1), "{st_mode=S_IFREG|0644, st_size=124494, ...}");
}

TEST(TestParseLine, WithPidClosePipeUnfinished) {
	const char* input = "[pid  5557] 19:58:35.831752 close(4<pipe:[52233]> <unfinished ...>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "close");
	EXPECT_EQ(line.pid(), 5557);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), Line::no_time);
	EXPECT_EQ(line.time_as_string(), "19:58:35.831752000");
	EXPECT_EQ(line.args_string(), "4<pipe:[52233]>");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "4<pipe:[52233]>");
}

TEST(TestParseLine, WithPidCloseFileUnfinished) {
	const char* input = "[pid  5601] 19:59:20.547608 close(3</usr/lib64/libcap.so.2.24> <unfinished ...>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "close");
	EXPECT_EQ(line.pid(), 5601);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), Line::no_time);
	EXPECT_EQ(line.time_as_string(), "19:59:20.547608000");
	EXPECT_EQ(line.args_string(), "3</usr/lib64/libcap.so.2.24>");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "3</usr/lib64/libcap.so.2.24>");
}

TEST(TestParseLine, WithPidWait4Unfinished) {
	const char* input = "[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "wait4");
	EXPECT_EQ(line.pid(), 4233);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), Line::no_time);
	EXPECT_EQ(line.time_as_string(), "19:58:35.831781000");
	EXPECT_EQ(line.args_string(), "-1, ");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "-1");
}

TEST(TestParseLine, WithPidIoctlUnfinished) {
	const char* input = "[pid  4233] 19:58:40.705906 ioctl(255</dev/pts/2>, TIOCGPGRP <unfinished ...>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "ioctl");
	EXPECT_EQ(line.pid(), 4233);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), Line::no_time);
	EXPECT_EQ(line.time_as_string(), "19:58:40.705906000");
	EXPECT_EQ(line.args_string(), "255</dev/pts/2>, TIOCGPGRP");
	EXPECT_EQ(line.args_count(), 2);
	EXPECT_EQ(line.arg_single(0), "255</dev/pts/2>");
	EXPECT_EQ(line.arg_single(1), "TIOCGPGRP");
}

TEST(TestParseLine, WithPidDup2Unfinished) {
	const char* input = "[pid  5602] 19:59:20.543027 dup2(3<pipe:[52643]>, 0</dev/pts/2> <unfinished ...>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "dup2");
	EXPECT_EQ(line.pid(), 5602);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), Line::no_time);
	EXPECT_EQ(line.time_as_string(), "19:59:20.543027000");
	EXPECT_EQ(line.args_string(), "3<pipe:[52643]>, 0</dev/pts/2>");
	EXPECT_EQ(line.args_count(), 2);
	EXPECT_EQ(line.arg_single(0), "3<pipe:[52643]>");
	EXPECT_EQ(line.arg_single(1), "0</dev/pts/2>");
}

TEST(TestParseLine, WithPidFstatUnfinished) {
	const char* input = R"([pid  5602] 19:59:20.547638 fstat(3</usr/lib64/libpcre.so.1.2.7>,  <unfinished ...>)";

	Line line(input);
	EXPECT_EQ(line.function_name(), "fstat");
	EXPECT_EQ(line.pid(), 5602);
	EXPECT_EQ(line.return_value(), "");
	EXPECT_EQ(line.execution_time(), Line::no_time);
	EXPECT_EQ(line.time_as_string(), "19:59:20.547638000");
	EXPECT_EQ(line.args_string(), "3</usr/lib64/libpcre.so.1.2.7>, ");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "3</usr/lib64/libpcre.so.1.2.7>");
}

TEST(TestParseLine, WithPidReadResumed) {
	const char* input = "[pid  5562] 19:58:40.705844 <... read resumed> "", 1) = 0 <0.000305>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "read");
	EXPECT_EQ(line.pid(), 5562);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000305);
	EXPECT_EQ(line.time_as_string(), "19:58:40.705844000");
	EXPECT_EQ(line.args_string(), """, 1");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "1");
}

TEST(TestParseLine, WithPidIoctlResumed) {
	const char* input = "[pid  4233] 19:58:40.705946 <... ioctl resumed> , [5562]) = 0 <0.000025>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "ioctl");
	EXPECT_EQ(line.pid(), 4233);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000025);
	EXPECT_EQ(line.time_as_string(), "19:58:40.705946000");
	EXPECT_EQ(line.args_string(), ", [5562]");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "[5562]");
}

TEST(TestParseLine, WithPidCloseOkResumed) {
	const char* input = "[pid  4233] 19:58:40.705863 <... close resumed> ) = 0 <0.000062>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "close");
	EXPECT_EQ(line.pid(), 4233);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000062);
	EXPECT_EQ(line.time_as_string(), "19:58:40.705863000");
	EXPECT_EQ(line.args_string(), "");
	EXPECT_EQ(line.args_count(), 0);
}

TEST(TestParseLine, WithPidCloseErrorResumed) {
	const char* input = "[pid  4233] 19:59:20.542122 <... close resumed> ) = -1 EBADF (Bad file descriptor) <0.000221>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "close");
	EXPECT_EQ(line.pid(), 4233);
	EXPECT_EQ(line.return_value(), "-1 EBADF (Bad file descriptor)");
	EXPECT_EQ(line.execution_time(), 0.000221);
	EXPECT_EQ(line.time_as_string(), "19:59:20.542122000");
	EXPECT_EQ(line.args_string(), "");
	EXPECT_EQ(line.args_count(), 0);
}

TEST(TestParseLine, WithPidDup2Resumed) {
	const char* input = "[pid  5602] 19:59:20.543099 <... dup2 resumed> ) = 0<pipe:[52643]> <0.000043>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "dup2");
	EXPECT_EQ(line.pid(), 5602);
	EXPECT_EQ(line.return_value(), "0<pipe:[52643]>");
	EXPECT_EQ(line.execution_time(), 0.000043);
	EXPECT_EQ(line.time_as_string(), "19:59:20.543099000");
	EXPECT_EQ(line.args_string(), "");
	EXPECT_EQ(line.args_count(), 0);
}

TEST(TestParseLine, WithPidFstatResumed) {
	const char* input = "[pid  5602] 19:59:20.547695 <... fstat resumed> {st_mode=S_IFREG|0755, st_size=467832, ...}) = 0 <0.000040>";

	Line line(input);
	EXPECT_EQ(line.function_name(), "fstat");
	EXPECT_EQ(line.pid(), 5602);
	EXPECT_EQ(line.return_value(), "0");
	EXPECT_EQ(line.execution_time(), 0.000040);
	EXPECT_EQ(line.time_as_string(), "19:59:20.547695000");
	EXPECT_EQ(line.args_string(), "{st_mode=S_IFREG|0755, st_size=467832, ...}");
	EXPECT_EQ(line.args_count(), 1);
	EXPECT_EQ(line.arg_single(0), "{st_mode=S_IFREG|0755, st_size=467832, ...}");
}

