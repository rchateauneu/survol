module straceparser;

import std;

using namespace std;

void Line::make_time(const smatch& mtch) {
	int hrs = stoi(mtch[1]);
	int mins = stoi(mtch[2]);
	int secs = stoi(mtch[3]);
	int microsecs = stoi(mtch[4]);
	m_timestamp = chrono::hours(hrs)
		+ chrono::minutes(mins)
		+ chrono::seconds(secs)
		+ chrono::microseconds(microsecs);
}

static vector<string> split_ignoring_commas(const string_view& input_string) {
    vector<string> parts;
    string current;
    stack<char> brackets; // keep track of '(', '{', '[', '<'

    enum class State { Normal, InDoubleQuote, InSingleQuote, InBlockComment, InLineComment };
    State state = State::Normal;

    const size_t string_len = input_string.size();
    for (size_t string_index = 0; string_index < string_len; ++string_index) {
        char current_char = input_string[string_index];

        // handle states first
        if (state == State::InBlockComment) {
            current.push_back(current_char);
            // look for end "*/"
            if (current_char == '*' && string_index + 1 < string_len && input_string[string_index + 1] == '/') {
                current.push_back(input_string[string_index + 1]);
                ++string_index;
                state = State::Normal;
            }
            continue;
        }

        if (state == State::InLineComment) {
            current.push_back(current_char);
            if (current_char == '\n') {
                state = State::Normal;
            }
            continue;
        }

        if (state == State::InDoubleQuote) {
            current.push_back(current_char);
            if (current_char == '\\') {
                // escape next char if any (keep it in token)
                if (string_index + 1 < string_len) {
                    current.push_back(input_string[string_index + 1]);
                    ++string_index;
                }
            }
            else if (current_char == '"') {
                state = State::Normal;
            }
            continue;
        }

        if (state == State::InSingleQuote) {
            current.push_back(current_char);
            if (current_char == '\\') {
                // escaped char inside single-quote
                if (string_index + 1 < string_len) {
                    current.push_back(input_string[string_index + 1]);
                    ++string_index;
                }
            }
            else if (current_char == '\'') {
                state = State::Normal;
            }
            continue;
        }

        // state == Normal
        // detect comment starts
        if (current_char == '/' && string_index + 1 < string_len) {
            char nxt = input_string[string_index + 1];
            if (nxt == '*') {
                current.push_back(current_char);
                current.push_back(nxt);
                ++string_index;
                state = State::InBlockComment;
                continue;
            }
            else if (nxt == '/') {
                current.push_back(current_char);
                current.push_back(nxt);
                ++string_index;
                state = State::InLineComment;
                continue;
            }
        }

        // detect quote starts
        if (current_char == '"') {
            current.push_back(current_char);
            state = State::InDoubleQuote;
            continue;
        }
        if (current_char == '\'') {
            current.push_back(current_char);
            state = State::InSingleQuote;
            continue;
        }

        // bracket handling
        if (current_char == '(' || current_char == '{' || current_char == '[' || current_char == '<') {
            brackets.push(current_char);
            current.push_back(current_char);
            continue;
        }
        if (current_char == ')' || current_char == '}' || current_char == ']' || current_char == '>') {
            if (!brackets.empty()) {
                char top = brackets.top();
                bool match = (top == '(' && current_char == ')') ||
                    (top == '{' && current_char == '}') ||
                    (top == '[' && current_char == ']') ||
                    (top == '<' && current_char == '>');
                if (match) brackets.pop();
                // else mismatched — still treat as a closing bracket character
            }
            current.push_back(current_char);
            continue;
        }

        // comma splitting: only when not inside any bracket/quote/comment
        if (current_char == ',' && brackets.empty()) {
            parts.push_back(current);
            current.clear();
            continue; // skip adding the comma into current
        }

        // normal char append
        current.push_back(current_char);
    }

    // push last token
    parts.push_back(current);
    return parts;
}

void Line::fill_from_match(const smatch& mtch) {
	make_time(mtch);
	m_args_split = split_ignoring_commas(m_args_all);
	transform(m_args_split.begin(), m_args_split.end(), m_args_split.begin(),
		[](const string& s) {
			string res = s; 
			// trim spaces
			size_t first = res.find_first_not_of(" \t");
			size_t last = res.find_last_not_of(" \t");
			if (first != string::npos && last != string::npos) {
				res = res.substr(first, last - first + 1);
			}
			else {
				res.clear(); // all spaces
			}
			return res;
		});

    // Last processing because of spurious commas.
    switch (m_state) {
	case LineState::Normal:
        break;
    case LineState::Unfinished:
		if (!m_args_split.empty() && m_args_split.back().empty()) {
			// Remove spurious empty argument at end.
			m_args_split.pop_back();
		}
        break;
    case LineState::Resumed:
        if (!m_args_split.empty() && m_args_split.front().empty()) {
            // Remove spurious empty argument at the beginning. There are not many elements.
			m_args_split.erase(m_args_split.begin());
        }
        break;
    default:
        throw runtime_error("Invalid state");
    }
}

string Line::time_as_string() const {
	return std::format("{:%H:%M:%S}", m_timestamp);
}

bool Line::fill_from_string_normal(const string& input, size_t offset) {
    // 11:22:33.444444 clone(x) = 123 <y>
    // 19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>
    static const regex rgx_strace_line_normal(
        // TODO: Broken for " = 3</usr/lib64/filename with spaces.txt> <0."
        R"(^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(.+)\s+<([\d\.]+)>?$)"
    );
    
    smatch matches; /* Internal compiler error in test.cpp if in the ixx file ?!?! Debug and release mode. */
	if (regex_search(input.cbegin() + offset, input.cend(), matches, rgx_strace_line_normal)) {
		m_state = LineState::Normal;
        m_function = matches[5];
        m_args_all = matches[6];
        m_return = matches[7];
        m_execution_time = stod(matches[8]);
        fill_from_match(matches);
		return true;
	}
	return false;
}


/*
19:58:40.704988 clone( <unfinished ...>
[pid  5557] 19:58:35.831752 close(4<pipe:[52233]> <unfinished ...>
[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>
[pid  4233] 19:58:40.705906 ioctl(255</dev/pts/2>, TIOCGPGRP <unfinished ...>

[pid  5562] 19:58:40.705844 <... read resumed> "", 1) = 0 <0.000305>
[pid  4233] 19:58:40.705863 <... close resumed> ) = 0 <0.000062>
[pid  4233] 19:58:40.705946 <... ioctl resumed> , [5562]) = 0 <0.000025>
[pid  4233] 19:59:20.542122 <... close resumed> ) = -1 EBADF (Bad file descriptor) <0.000221>

[pid  5602] 19:59:20.543027 dup2(3<pipe:[52643]>, 0</dev/pts/2> <unfinished ...>
[pid  5601] 19:59:20.543062 close(5<pipe:[52644]> <unfinished ...>
[pid  5602] 19:59:20.543099 <... dup2 resumed> ) = 0<pipe:[52643]> <0.000043>

// A stack per process.

[pid  5601] 19:59:20.547608 close(3</usr/lib64/libcap.so.2.24> <unfinished ...>
[pid  5602] 19:59:20.547638 fstat(3</usr/lib64/libpcre.so.1.2.7>,  <unfinished ...>
[pid  5601] 19:59:20.547662 <... close resumed> ) = 0 <0.000036>
[pid  5602] 19:59:20.547695 <... fstat resumed> {st_mode=S_IFREG|0755, st_size=467832, ...}) = 0 <0.000040>

*/
bool Line::fill_from_string_unfinished(const string& input, size_t offset) {
    static const regex rgx_strace_line_resume(
        // TODO: Broken for " = 3</usr/lib64/filename with spaces.txt> <0."
        R"(^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+([a-zA-Z0-9_]+)\((.*) <unfinished \.\.\.>$)"
    );
    smatch matches;
    if (regex_search(input.cbegin() + offset, input.cend(), matches, rgx_strace_line_resume)) {
		m_state = LineState::Unfinished;
        m_function = matches[5];
        m_args_all = matches[6];
        m_return = "";
        m_execution_time = no_time;
        fill_from_match(matches);
        return true;
    }
    return false;
}

/*
19:58:40.704988 clone( <unfinished ...>
[pid  5557] 19:58:35.831752 close(4<pipe:[52233]> <unfinished ...>
[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>
[pid  4233] 19:58:40.705906 ioctl(255</dev/pts/2>, TIOCGPGRP <unfinished ...>

[pid  5562] 19:58:40.705844 <... read resumed> "", 1) = 0 <0.000305>
[pid  4233] 19:58:40.705863 <... close resumed> ) = 0 <0.000062>
[pid  4233] 19:58:40.705946 <... ioctl resumed> , [5562]) = 0 <0.000025>
[pid  4233] 19:59:20.542122 <... close resumed> ) = -1 EBADF (Bad file descriptor) <0.000221>

[pid  5602] 19:59:20.543027 dup2(3<pipe:[52643]>, 0</dev/pts/2> <unfinished ...>
[pid  5601] 19:59:20.543062 close(5<pipe:[52644]> <unfinished ...>
[pid  5602] 19:59:20.543099 <... dup2 resumed> ) = 0<pipe:[52643]> <0.000043>

[pid  5601] 19:59:20.547608 close(3</usr/lib64/libcap.so.2.24> <unfinished ...>
[pid  5602] 19:59:20.547638 fstat(3</usr/lib64/libpcre.so.1.2.7>,  <unfinished ...>
[pid  5601] 19:59:20.547662 <... close resumed> ) = 0 <0.000036>
[pid  5602] 19:59:20.547695 <... fstat resumed> {st_mode=S_IFREG|0755, st_size=467832, ...}) = 0 <0.000040>
*/
bool Line::fill_from_string_resume(const string& input, size_t offset) {
    // 19:58:40.705844 <... read resumed> "", 1) = 0 <0.000305>
	static const regex rgx_strace_line_resume(
        // TODO: Broken for " = 3</usr/lib64/filename with spaces.txt> <0."
        R"(^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+<\.\.\.\s+([a-zA-Z0-9_]+)\s+resumed>\s+(.*)\)\s+=\s+(.+)\s+<([\d\.]+)>?$)"
    );
	smatch matches;
	if (regex_search(input.cbegin() + offset, input.cend(), matches, rgx_strace_line_resume)) {
		m_state = LineState::Resumed;
		m_function = matches[5];
		m_args_all = matches[6];
		m_return = matches[7];
		m_execution_time = stod(matches[8]);
        fill_from_match(matches);
        return true;
	}
	return false;
}

/*
* [pid 23946] 08:53:31.347538 exit_group(0) = ?
*/
bool Line::fill_from_string_exit_group(const string& input, size_t offset) {
    static const regex rgx_strace_line_exit_group(
        R"(^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+exit_group\(0\)\s+=\s+\?$)"
    );
    smatch matches;
    if (regex_search(input.cbegin() + offset, input.cend(), matches, rgx_strace_line_exit_group)) {
        m_state = LineState::Normal;
        m_function = "exit_group";
        m_args_all = matches[5];
        m_return = "?";
        m_execution_time = no_time;
        fill_from_match(matches);
        return true;
    }
    return false;
}

// [pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>
static pair<Line::pid_type, size_t> get_pid(const string& input_line) {
	static const regex rgx_pid(R"(^\[pid\s+(\d+)\]\s+)");
	smatch matches;
	if (regex_search(input_line, matches, rgx_pid)) {
		int pid = stoi(matches[1]);
		size_t pid_end = matches.position(0) + matches.length(0);
		return { pid, pid_end };
	}
	return { Line::no_pid, 0 };
}

/*
19:58:40.704988 clone( <unfinished ...>
[pid  5557] 19:58:35.831752 close(4<pipe:[52233]> <unfinished ...>
[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>
[pid  4233] 19:58:40.705906 ioctl(255</dev/pts/2>, TIOCGPGRP <unfinished ...>

[pid  5562] 19:58:40.705844 <... read resumed> "", 1) = 0 <0.000305>
[pid  4233] 19:58:40.705863 <... close resumed> ) = 0 <0.000062>
[pid  4233] 19:58:40.705946 <... ioctl resumed> , [5562]) = 0 <0.000025>
[pid  4233] 19:59:20.542122 <... close resumed> ) = -1 EBADF (Bad file descriptor) <0.000221>

[pid  5602] 19:59:20.543027 dup2(3<pipe:[52643]>, 0</dev/pts/2> <unfinished ...>
[pid  5601] 19:59:20.543062 close(5<pipe:[52644]> <unfinished ...>
[pid  5602] 19:59:20.543099 <... dup2 resumed> ) = 0<pipe:[52643]> <0.000043>

// A stack per process.

[pid  5601] 19:59:20.547608 close(3</usr/lib64/libcap.so.2.24> <unfinished ...>
[pid  5602] 19:59:20.547638 fstat(3</usr/lib64/libpcre.so.1.2.7>,  <unfinished ...>
[pid  5601] 19:59:20.547662 <... close resumed> ) = 0 <0.000036>
[pid  5602] 19:59:20.547695 <... fstat resumed> {st_mode=S_IFREG|0755, st_size=467832, ...}) = 0 <0.000040>

*/


Line::Line(const string& content) {
    /*
    * 08:14:22.592439 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=27127, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
    * [pid 27130] 08:14:25.607495 exit_group(0) = ?
    */
    auto [pid, offset] = get_pid(content);
	if (fill_from_string_normal(content, offset)) {
        m_pid = pid;
    }
	else
    if (fill_from_string_unfinished(content, offset)) {
        m_pid = pid;
    }
    else
    if (fill_from_string_resume(content, offset)) {
        m_pid = pid;
    }
    else
    if (fill_from_string_exit_group(content, offset)) {
            m_pid = pid;
        }
    else
    {
		throw runtime_error("Line: Invalid strace line format: " + content);
	}
}


#ifdef DOC
19:58:30.681451 read(0</dev/pts/2>, "l", 1) = 1 <4.697032>
19:58:35.378646 write(2</dev/pts/2>, "l", 1) = 1 <0.000023>
19:58:35.830656 ioctl(0</dev/pts/2>, SNDCTL_TMR_STOP or TCSETSW, {B38400 opost isig icanon echo ...}) = 0 <0.000017>
19:58:35.830922 pipe([3<pipe:[52233]>, 4<pipe:[52233]>]) = 0 <0.000016>
19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>
[pid  4233] 19:58:35.831382 close(3<pipe:[52233]>) = 0 <0.000016>
[pid  4233] 19:58:35.831781 wait4(-1,  <unfinished ...>
[pid  5557] 19:58:35.831817 <... close resumed> ) = 0 <0.000041>
[pid  5557] 19:58:35.832440 execve("/usr/bin/ls", ["ls", "--color=auto"], [/* 36 vars */]) = 0 <0.000333>
[pid  5557] 19:58:35.832893 brk(NULL)   = 0x196e000 <0.000011>
[pid  5557] 19:58:35.832952 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fb6a4537000 <0.000015>
[pid  5557] 19:58:35.833033 open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000016>
[pid  5557] 19:58:35.833106 fstat(3</etc/ld.so.cache>, {st_mode=S_IFREG|0644, st_size=124494, ...}) = 0 <0.000012>
#endif

class FileNode {
public:
	// 0</dev/pts/2>
    FileNode() {}
	FileNode(const string& arg) {}
};

/// <summary>
/// open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3</etc/ld.so.cache> <0.000018>
/// </summary>
class SystemCall_open : public SystemCall {
    string m_filename;
    string m_parameters;
public:
    inline static const string m_static_function_name = "open";
    static const size_t m_expected_args_count = 2;
    SystemCall_open(const Line& line)
        : m_filename(line.arg_single(0))
        , m_parameters(line.arg_single(1))
    {}
};

/// <summary>
/// openat(AT_FDCWD, "/proc", O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC) = 5</proc> <0.000009>
/// </summary>
class SystemCall_openat : public SystemCall {
    string m_flag;
    string m_filename;
    string m_parameters;
public:
    inline static const string m_static_function_name = "openat";
    static const size_t m_expected_args_count = 3;
    SystemCall_openat(const Line& line)
        : m_flag(line.arg_single(0))
        , m_filename(line.arg_single(1))
        , m_parameters(line.arg_single(2))
    {}
};

/// <summary>
/// read(0</dev/pts/2>, "l", 1)
/// </summary>
class SystemCall_read : public SystemCall {
    FileNode m_file_node;
    string m_buffer;
    size_t m_length;
public:
    inline static const string m_static_function_name = "read";
    static const size_t m_expected_args_count = 3;
    SystemCall_read(const Line& line)
        : m_file_node(line.arg_single(0))
        , m_buffer(line.arg_single(1))
        , m_length(stoi(line.arg_single(2)))
    {}
};

/// <summary>
/// write(2</dev/pts/2>, "s", 1)
/// </summary>
class SystemCall_write : public SystemCall {
    FileNode m_file_node;
    string m_buffer;
    size_t m_length;
public:
    inline static const string m_static_function_name = "write";
    static const size_t m_expected_args_count = 3;
    SystemCall_write(const Line& line)
        : m_file_node(line.arg_single(0))
        , m_buffer(line.arg_single(1))
        , m_length(stoi(line.arg_single(2)))
    {}
};

/// <summary>
/// pipe([3<pipe:[52233]>, 4<pipe:[52233]>])
/// </summary>
class SystemCall_pipe : public SystemCall {
    FileNode m_file_node0;
    FileNode m_file_node1;
public:
    inline static const string m_static_function_name = "pipe";
    static const size_t m_expected_args_count = 1;
    SystemCall_pipe(const Line& line)
    {
        const string& arg0 = line.arg_single(0);
        if (arg0.front() != '[' || arg0.back() != ']')
            throw runtime_error("Invalid pipe argument");
        vector<string> pipes_vec = split_ignoring_commas(string_view(arg0).substr(1, arg0.size() - 2));
        m_file_node0 = FileNode(pipes_vec.at(0));
        m_file_node1 = FileNode(pipes_vec.at(1));
    }
};

/// <summary>
/// clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0)
/// </summary>
class SystemCall_clone : public SystemCall {
    string m_child_stack;
    string m_flags;
    string m_child_tidptr;
public:
    inline static const string m_static_function_name = "clone";
    static const size_t m_expected_args_count = 3;
    SystemCall_clone(const Line& line)
        : m_child_stack(line.arg_single(0))
        , m_flags(line.arg_single(1))
        , m_child_tidptr(line.arg_single(2))
    {}
};

/// <summary>
/// close(3<pipe:[52233]>)
/// </summary>
class SystemCall_close : public SystemCall {
    FileNode m_file_node;
    string m_buffer;
    size_t m_length;
public:
    inline static const string m_static_function_name = "close";
    static const size_t m_expected_args_count = 1;
    SystemCall_close(const Line& line)
        : m_file_node(line.arg_single(0))
    {}
};

/// <summary>
/// wait4(-1,  <unfinished ...> ... )
/// </summary>
/// 

/* The logic of how strace processes wait4 is not very clear :

            19:58:35.830990 clone(child_stack=0, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f3b1ca779d0) = 5557 <0.000185>
[pid  4233] 19:58:35.831781 wait4(-1, < unfinished ...>
            19:58:35.841846 < ... wait4 resumed > [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], WSTOPPED | WCONTINUED, NULL) = 5557 < 0.010057 >

=> wait4 waits for -1 and finishes in another process.

            14:54:00.522992 vfork( <unfinished ...>
[pid  1338] 14:54:00.523319 <... vfork resumed> ) = 1342 <0.000312>
[pid  1338] 14:54:00.523342 wait4(-1,  <unfinished ...>
[pid  1342] 14:54:00.529260 vfork( <unfinished ...>
[pid  1342] 14:54:00.534707 <... vfork resumed> ) = 1343 <0.005436>
[pid  1342] 14:54:00.534728 wait4(1343,  <unfinished ...>
[pid  1342] 14:54:00.585987 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 1343 <0.051249>
[pid  1342] 14:54:00.586153 vfork( <unfinished ...>
[pid  1342] 14:54:00.586547 <... vfork resumed> ) = 1344 <0.000380>
[pid  1342] 14:54:00.586565 wait4(1344,  <unfinished ...>
[pid  1342] 14:54:00.610064 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 1344 <0.023491>
            14:54:00.610657 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 1342 <0.087308>

=> wait4 waits for -1 and finishes in the same process.
=> wait4 waits for a specific pid and finishes in another process.


            08:53:31.301860 vfork( <unfinished ...>
[pid 23944] 08:53:31.304901 <... vfork resumed> ) = 23945 <0.003032>
[pid 23944] 08:53:31.304921 wait4(23945,  <unfinished ...>
            08:53:31.335463 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23945 <0.030535>
            08:53:31.335744 vfork( <unfinished ...>
[pid 23944] 08:53:31.336179 <... vfork resumed> ) = 23946 <0.000427>
[pid 23944] 08:53:31.336196 wait4(23946,  <unfinished ...>
            08:53:31.348242 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23946 <0.012039>
            08:53:31.349322 vfork( <unfinished ...>
[pid 23944] 08:53:31.349554 <... vfork resumed> ) = 23947 <0.000222>
[pid 23944] 08:53:31.349571 wait4(23947,  <unfinished ...>
[pid 23947] 08:53:31.353394 vfork( <unfinished ...>
[pid 23947] 08:53:31.353725 <... vfork resumed> ) = 23948 <0.000323>
[pid 23947] 08:53:31.353797 wait4(23948,  <unfinished ...>
[pid 23947] 08:53:31.478920 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23948 <0.125108>
            08:53:31.479748 <... wait4 resumed> [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 23947 <0.130171>

=> wait4 waits for a specific pid and finishes in another process.

*/ 
class SystemCall_wait4 : public SystemCall {
    int m_pid;
public:
    inline static const string m_static_function_name = "wait4";
    static const size_t m_expected_args_count = 1;
    SystemCall_wait4(const Line& line)
        : m_pid(stoi(line.arg_single(0)))
    {}
};

/// <summary>
/// execve("/usr/bin/ls", ["ls", "--color=auto"], [/* 36 vars */])
/// </summary>
class SystemCall_execve : public SystemCall {
    string m_executable_name;
    string m_command_args;
public:
    inline static const string m_static_function_name = "execve";
    static const size_t m_expected_args_count = 3;
    SystemCall_execve(const Line& line)
        : m_executable_name(line.arg_single(0))
        , m_command_args(line.arg_single(1))
    {
    }
};

/// <summary>
/// exit_group(0) = ?
/// </summary>
class SystemCall_exit_group : public SystemCall {
public:
    inline static const string m_static_function_name = "exit_group";
    static const size_t m_expected_args_count = 1;
    SystemCall_exit_group(const Line& line)
    {}
};

/// <summary>
/// fstat(3</proc/filesystems>, {st_mode=S_IFREG|0444, st_size=0, ...})
/// </summary>
class SystemCall_fstat : public SystemCall {
    FileNode m_file_node;
    string m_buffer;
public:
    inline static const string m_static_function_name = "fstat";
    static const size_t m_expected_args_count = 2;
    SystemCall_fstat(const Line& line)
        : m_file_node(line.arg_single(0))
        , m_buffer(line.arg_single(1))
    {}
};

/// <summary>
/// vfork( <unfinished ...>
/// </summary>
class SystemCall_vfork : public SystemCall {
    FileNode m_file_node;
    string m_buffer;
public:
    inline static const string m_static_function_name = "vfork";
    static const size_t m_expected_args_count = 0;
    SystemCall_vfork(const Line& line)
        : m_file_node(line.arg_single(0))
        , m_buffer(line.arg_single(1))
    {}
};

#ifdef MODEL
/// <summary>
/// 
/// </summary>
class SystemCall_XXXX : public SystemCall {
    FileNode m_file_node;
    string m_buffer;
    size_t m_length;
public:
    inline static const string m_static_function_name = "XXXX";
    static const size_t m_expected_args_count = 999;
    SystemCall_XXXX(const Line& line)
        : m_file_node(line.arg_single(0))
        , m_buffer(line.arg_single(1))
        , m_length(stoi(line.arg_single(2)))
    {}
};
#endif

/// <summary>
/// Item
/// </summary>
struct Item {
	const string& m_function_name;
	function < shared_ptr<SystemCall>(const Line&) > m_generator;

    template<typename SystemCallDerived>
	static Item factory() {
		return Item{
			SystemCallDerived::m_static_function_name,
			[](const Line & line) -> shared_ptr<SystemCall> {
                if (SystemCallDerived::m_expected_args_count != line.args_count()) {
					throw runtime_error("Function " + SystemCallDerived::m_static_function_name +
						" expects " + to_string(SystemCallDerived::m_expected_args_count) +
						" arguments, but line has " + to_string(line.args_count()) + " arguments.");
                }
                return make_shared<SystemCallDerived>(line);
            }
		};
	}
};

struct ItemEqual
{
    using is_transparent = void;

    bool operator()(const Item& lhs, const Item& rhs) const
    {
        return lhs.m_function_name == rhs.m_function_name;
    }

    bool operator()(const Item& lhs, const string& rhs) const
    {
        return lhs.m_function_name == rhs;
    }

    bool operator()(const string& lhs, const Item& rhs) const
    {
        return lhs == rhs.m_function_name;
    }
};

struct ItemHash
{
    using is_transparent = void;

    std::size_t operator()(const Item& item) const
    {
        return hash<string>{}(item.m_function_name);
    }

    std::size_t operator()(const string& string_key) const
    {
        return hash<string>{}(string_key);
    }
};

/*
This is not ideal because the arguments of the resumed call must be moved, but there are not many of them.
*/
void Line::merge_with_unfinished_call(const Line& unfinished_line) {
    if (m_function != unfinished_line.m_function) {
        throw runtime_error("No match of last unfinished call");
    }
    m_args_split.insert(m_args_split.begin(), unfinished_line.m_args_split.begin(), unfinished_line.m_args_split.end());
}


shared_ptr<SystemCall> Line::create_system_call()
{
    static const unordered_set <Item, ItemHash, ItemEqual>
        set_classes
    {
        Item::factory<SystemCall_open>(),
        Item::factory<SystemCall_openat>(),
        Item::factory<SystemCall_read>(),
        Item::factory<SystemCall_write>(),
        Item::factory<SystemCall_close>(),
        Item::factory<SystemCall_fstat>(),
        Item::factory<SystemCall_pipe>(),
        Item::factory<SystemCall_clone>(),
        Item::factory<SystemCall_wait4>(),
        Item::factory<SystemCall_execve>(),
        Item::factory<SystemCall_exit_group>(),
        Item::factory<SystemCall_vfork>(),
    };

	static const unordered_set<string> unsupported_functions
	{
		"ioctl",
		"brk",
		"mmap",
        "mprotect",
        "munmap",
        "getdents",
        "arch_prctl",
        // add more as needed
	};
    if (unsupported_functions.contains(m_function)) {
        return nullptr;
    }

    static unordered_map<Line::pid_type, vector<Line>> unfinished_calls;

    switch (m_state) {
        case LineState::Normal:
            break;
        case LineState::Unfinished:
            unfinished_calls[m_pid].push_back(*this);
            return nullptr;
        case LineState::Resumed:
            {
                auto pid_unfinished_calls = unfinished_calls[m_pid];
                if (pid_unfinished_calls.empty()) {
                    throw runtime_error("Cannot find unfinished call. Pid=" + to_string(m_pid) + " function=" + m_function);
                }
                const Line& ref_last_unfinished_call = pid_unfinished_calls.back();
                merge_with_unfinished_call(ref_last_unfinished_call);
                pid_unfinished_calls.pop_back();
            }
            break;
        default:
            throw runtime_error("Invalid state");
    }
    auto generator = set_classes.find(m_function);

    if (generator == set_classes.end()) {
        throw runtime_error("Cannot find function:" + m_function);
    }
	shared_ptr<SystemCall> ptr = generator->m_generator(*this);
    return ptr;
}

STraceParser::STraceParser(const string& filename)
    : m_filename(filename) {
    m_file.open(m_filename);
}

pair<Line::LineState, TripleStore> STraceParser::get_next_triplestore() {
    string input_string;
    getline(m_file, input_string);

    if (input_string.empty()) {
        return make_pair(Line::LineState::EndOfFile, TripleStore());
    }

    Line line(input_string);
    shared_ptr<SystemCall> system_call = line.create_system_call();
    if (!system_call) {
        return make_pair(Line::LineState::Unsupported, TripleStore());
    }

    TripleStore triple_store = system_call->create_triplestore();
    return make_pair(Line::LineState::Normal, triple_store);
}

STraceParser::~STraceParser() {}
