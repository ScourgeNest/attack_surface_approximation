class Colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    CYAN = "\033[1;36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

class StaticAnalysisConfig:
    FORMAT_STRING_FUNCTIONS = ['printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf']

    # Aceasta lista va fi populata si dinamic cu nm -D in timpul rularii
    LIBC_EXACT_NAMES = [
        'deregister_tm_clones', 'register_tm_clones', 'frame_dummy'
    ]

    GHIDRA_TYPE_REPLACEMENTS = [
        ("undefined8", "long long"),
        ("undefined4", "int"),
        ("undefined2", "short"),
        ("undefined1", "char"),
        ("undefined",  "char"),
        ("ulonglong",  "unsigned long long"),
        ("longlong",   "long long"),
        ("ulong",      "unsigned long"),
        ("uint",       "unsigned int"),
        ("ushort",     "unsigned short"),
        ("qword",      "unsigned long long"),
        ("dword",      "unsigned int"),
        ("word",       "unsigned short"),
        ("byte",       "unsigned char"),
        ("bool",       "int"),
        ("code",       "void"),
    ]

    GHIDRA_PREAMBLE = """
typedef int size_t;
typedef long ssize_t;
typedef unsigned int mode_t;
typedef int pid_t;
typedef int __gid_t;
typedef int __uid_t;
typedef int __pid_t;
typedef int FILE;
typedef void va_list;
typedef long time_t;
typedef int wint_t;
typedef struct { int dummy; } sockaddr;
int printf(char *fmt, ...);
int fprintf(int stream, char *fmt, ...);
int sprintf(char *str, char *fmt, ...);
int snprintf(char *str, int size, char *fmt, ...);
int dprintf(int fd, char *fmt, ...);
"""
    GHIDRA_PREAMBLE_LEN = len(GHIDRA_PREAMBLE.splitlines())

class Configuration:
    class Fuzzer:
        GENERATE_RANDOM_BASELINE_ARGUMENTS = False

    class QBDIAnalysis:
        IMAGE_TAG = "qbdi_args_fuzzing"
        HOST_FOLDER = "/tmp/qbdi/"
        HOST_DICTIONARIES_FOLDER = HOST_FOLDER + "dictionaries/"
        HOST_EXECUTABLE_FOLDER = HOST_FOLDER + "target/"
        HOST_EXECUTABLE = HOST_EXECUTABLE_FOLDER + "target"
        HOST_RESULTS_FOLDER = HOST_FOLDER + "results/"
        CONTAINER_SO_FOLDER = "/home/docker"
        CONTAINER_EXECUTABLE_FOLDER = "/home/docker/target/"
        CONTAINER_EXECUTABLE = CONTAINER_EXECUTABLE_FOLDER + "target"
        CONTAINER_RESULTS_FOLDER = "/home/docker/results/"
        CONTAINER_TEMP_FILE = "/tmp/canary.opencrs"
