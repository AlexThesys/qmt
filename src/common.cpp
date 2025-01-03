#include "common.h"

#include <nmmintrin.h>

#pragma comment(lib, "dbghelp.lib")

const char* page_state[] = { "MEM_COMMIT", "MEM_FREE", "MEM_RESERVE" };
const char* page_type[] = { "MEM_IMAGE", "MEM_MAPPED", "MEM_PRIVATE" };
const char* page_protect[] = { "PAGE_EXECUTE", "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY", "PAGE_NOACCESS", "PAGE_READONLY",
                                    "PAGE_READWRITE", "PAGE_WRITECOPY", "PAGE_TARGETS_INVALID", "UNKNOWN" };

const char* unknown_command = "Unknown command.\n";
const char* command_not_implemented = "Command not implemented.\n";
static const char* error_parsing_the_input = "Error parsing the input.\n";
static const char* max_path_len_error = "Path exceeds the maximum of %lu characters.\n";
static const char* cmd_args[] = { "-h", "--help", "-f", "--show-failed-readings", "-t=", "--threads=", "-v", "--version",
                                "-p", "--process", "-d", "--dump", "-b=", "--blocks=", "-n", "--no-page-caching", "-c", "--clear-standby-list", 
                                "-s", "--disable-symbols"};
static constexpr size_t cmd_args_size = _countof(cmd_args) / 2; // given that every option has a long and a short forms
static const char* program_version = "Version 0.3.9";
static const char* program_name = "Quick Memory Tools";

int g_max_threads = INVALID_THREAD_NUM;
LONG64 g_num_alloc_blocks = DEFAULT_ALLOC_BLOCKS;
int g_show_failed_readings = 0;
inspection_mode g_inspection_mode = inspection_mode::im_none;
int g_purge_standby_pages = 0;
int g_disable_page_caching = 0;
int g_disable_symbols = 0;

static void clear_screen();

static constexpr int check_architecture_ct() {
#if defined(__x86_64__) || defined(_M_X64)
    return 1;
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return 1;
#else
    return 0;
#endif
}
static_assert(check_architecture_ct(), "Only x86-64 architecture is supported at the moment!");

int check_architecture_rt() {
    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    return int(SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
        || SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL);
}

const char* get_page_state(DWORD state) {
    const char *result = NULL;
    switch (state) {
    case MEM_COMMIT:
        result = page_state[0];
        break;
    case MEM_FREE:
        result = page_state[1];
        break;
    case MEM_RESERVE:
        result = page_state[2];
        break;
    }
    return result;
}

void print_page_type(DWORD state) {
    printf("Type:");
    if (state == MEM_IMAGE) {
        printf(" %s\n", page_type[0]);
    } else {
        if (state & MEM_MAPPED) {
            printf(" %s ", page_type[1]);
        }
        if (state & MEM_PRIVATE) {
            printf(" %s ", page_type[2]);
        }
        puts("");
    }
}

const char* get_page_protect(DWORD state) {
    // lets not comlicate things with other available options for now
    state &= ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);

    const char* result;
    switch (state) {
    case PAGE_EXECUTE:
        result = page_protect[0];
        break;
    case PAGE_EXECUTE_READ:
        result = page_protect[1];
        break;
    case PAGE_EXECUTE_READWRITE:
        result = page_protect[2];
        break;
    case PAGE_EXECUTE_WRITECOPY:
        result = page_protect[3];
        break;
    case PAGE_NOACCESS:
        result = page_protect[4];
        break;
    case PAGE_READONLY:
        result = page_protect[5];
        break;
    case PAGE_READWRITE:
        result = page_protect[6];
        break;
    case PAGE_WRITECOPY:
        result = page_protect[7];
        break;
    case PAGE_TARGETS_INVALID:
        result = page_protect[8];
        break;
    default:
        result = page_protect[9];
        break;
    }
    return result;
}

bool too_many_results(size_t num_lines, bool redirected, bool precise) {
    if (redirected || (num_lines < TOO_MANY_RESULTS)) {
        return false;
    }
    printf("Would you like to display%s%llu results? y/n ", (precise ? " " : " more than "), num_lines);
    const char ch = static_cast<char>(getchar());
    while ((getchar()) != '\n'); // flush stdin
    puts("");
    return !(ch == 'y' || ch == 'Y');
}

static void parse_input(char* pattern, search_data_info *data, input_type in_type) {
    if ((data->pdata.pattern_len + 1) > MAX_PATTERN_LEN) {
        fprintf(stderr, "Pattern exceeded maximum size of %d. Exiting...\n", MAX_PATTERN_LEN);
        data->type = it_error_type;
        return;
    }

    switch (in_type) {
    case input_type::it_hex_string : {
        int64_t pattern_len = data->pdata.pattern_len;
        if (pattern_len <= 1) {
            fprintf(stderr, "Hex string is shorter than 1 byte.\n");
            data->type = it_error_type;
            break;
        }
        if (pattern_len & 0x01) {
            pattern_len--;
            puts("\n<!> Hex string contains an extra nibble - discarded the last one..");
        }
        char byte[4] = { 0, 0, 0, 0 };
        char* end;
        for (int i = 0, j = 0; i < pattern_len; i += 2, j++) {
            memcpy(byte, (pattern + i), 2);
            uint32_t value = strtoul(byte, &end, 0x10);
            const int is_hex = ((end - byte) == 2);
            if (!is_hex) {
                data->type = it_error_type;
                return;
            }
            pattern[j] = (char)value;
        }

        pattern_len /= 2;
        pattern[pattern_len] = 0;

        data->type = it_hex_string;
        data->pdata.pattern = pattern;
        data->pdata.pattern_len = pattern_len;

        puts("\nSearching for a hex string...");
        break;
    }
    case input_type::it_hex_value : {
        uint64_t value = 0;
        char* end;
        value = strtoull(pattern, &end, 0x10);
        const int is_hex = (pattern != end);
        if (!is_hex) {
            data->type = it_error_type;
            break;
        }
        data->type = it_hex_value;
        data->value = value;
        data->pdata.pattern = (const char*)&data->value;
        size_t extra_char = 0;
        if (*end == 'h' || *end == 'H') {
            data->pdata.pattern_len = size_t(end - pattern);
        } else if (pattern[0] == '0' && (pattern[1] == 'x' || pattern[1] == 'X')) {
            data->pdata.pattern_len = size_t(end - pattern);
            data->pdata.pattern_len -= 2;
        } else {
            data->pdata.pattern_len = size_t(end - pattern);
        }
        extra_char = data->pdata.pattern_len & 0x01;
        data->pdata.pattern_len = (data->pdata.pattern_len + extra_char) / 2;
        if (data->pdata.pattern_len <= sizeof(uint64_t)) {
            puts("\nSearching for a hex value...");
        } else {
            fprintf(stderr, "Max supported hex value size: %d bytes!\n", (int)sizeof(uint64_t));
            data->type = it_error_type;
        }
        break;
    }
    case input_type::it_ascii_string : 
        data->type = it_ascii_string;
        data->pdata.pattern = pattern;
        pattern[data->pdata.pattern_len] = 0;
        puts("\nSearching for an ascii string...");
        break;
    default : 
        data->type = it_error_type;
        break;
    }
}

const uint8_t* strstr_u8(const uint8_t* str, size_t str_sz, const uint8_t* substr, size_t substr_sz) {
    constexpr size_t step =  sizeof(__m128i) / sizeof(uint8_t);

    if (/*!substr_sz || */(str_sz < substr_sz)) {
        return NULL;
    }
    const __m128i first = _mm_set1_epi8(substr[0]);
    const __m128i last = _mm_set1_epi8(substr[substr_sz - 1]);
    const uint8_t skip_first = (uint8_t)(substr_sz > 2);
    const size_t cmp_size = substr_sz - (1llu << skip_first);

    for (size_t j = 0, sz = str_sz - substr_sz; j <= sz; j += step) {
        const uint8_t* f = str + j;
        const uint8_t* l = str + j + substr_sz - 1;
        __m128i xmm0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(f));
        __m128i xmm1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(l));

        xmm0 = _mm_cmpeq_epi8(first, xmm0);
        xmm1 = _mm_cmpeq_epi8(last, xmm1);
        xmm0 = _mm_and_si128(xmm0, xmm1);

        uint32_t mask = (uint32_t)_mm_movemask_epi8(xmm0);

        const uint8_t max_offset = (uint8_t)_min(step, str_sz - (j + substr_sz) + 1);
        const uint32_t max_offset_mask = (1 << max_offset) - 1;
        mask &= max_offset_mask;
        unsigned long bit = 0;

        while (_BitScanForward(&bit, mask)) {
            const uint32_t offset = bit;
            const uint8_t* m0 = str + j + offset + skip_first;
            const uint8_t* m1 = substr + skip_first;
            if (memcmp(m0, m1, cmp_size) == 0)
                return (str + j + offset);

            mask ^= (1 << bit); // clear bit
        }
    }

    return NULL;
}

static void print_help() {
    puts("\n*** The program has to be launched in either process or dump inspection mode. ***\n");
    puts("-p || --process\t\t\t\t\t -- launch in process inspection mode");
    puts("-d || --dump\t\t\t\t\t -- launch in dump inspection mode\n");
    puts("-t=<num_threads> || --threads=<num_threads>\t -- limit the number of worker threads");
    puts("-b=<N> || --block_info=<N>\t\t\t -- alloc block_info size == (dwAllocationGranularity * N), N=[1-8]");
    puts("-f || --show-failed-readings\t\t\t -- show the regions, that failed to be read (process mode only)");
    puts("-h || --help\t\t\t\t\t -- show help (this message)");
    puts("-v || --version\t\t\t\t\t -- show version");
    puts("-n || --no-page-caching\t\t\t\t -- force disable page caching (dump mode only)");
#ifndef DISABLE_STANDBY_LIST_PURGE
    puts("-c || --clear-standby-list\t\t\t -- clear standby physical pages (dump mode only)");
#endif // DISABLE_STANDBY_LIST_PURGE
    puts("-s || --disable-symbols\t\t\t\t -- disable symbol resolution");
    puts("");
}

bool parse_cmd_args(int argc, const char** argv) {
    if (argc > (cmd_args_size + 1)) {
        fprintf(stderr, "Too many arguments provided: some will be discarded.\n");
    }

    uint32_t selected_options = 0;;
    for (int i = 1, sz = _min((int)cmd_args_size, argc); i < sz; i++) {
        if ((0 == strcmp(argv[i], cmd_args[0])) || (0 == strcmp(argv[i], cmd_args[1]))) { // help
            print_help();
            selected_options |= 1 << 0;
            return false;
        } else if ((0 == strcmp(argv[i], cmd_args[2])) || (0 == strcmp(argv[i], cmd_args[3]))) { // display failed reads
            g_show_failed_readings = 1;
            selected_options |= 1 << 2;
        } else if ((argv[i] == strstr(argv[i], cmd_args[4])) || (argv[i] == strstr(argv[i], cmd_args[5]))) { // threads
            const char* num_t = (argv[i][1] == '-') ? (argv[i] + strlen(cmd_args[5])) : (argv[i] + strlen(cmd_args[4]));
            char* end = NULL;
            size_t arg_len = strlen(num_t);
            DWORD num_threads = strtoul(num_t, &end, is_hex(num_t, arg_len) ? 16 : 10);
            if (num_t != end) {
                num_threads = _max(1, num_threads);
                g_max_threads = _min(num_threads, MAX_THREAD_NUM);
            }
            selected_options |= 1 << 3;
        } else if ((0 == strcmp(argv[i], cmd_args[6])) || (0 == strcmp(argv[i], cmd_args[7]))) { // version
            puts("");
            puts(program_name);
            puts(program_version);
            puts("");
            selected_options |= 1 << 4;
            return false;
        } else if ((0 == strcmp(argv[i], cmd_args[8])) || (0 == strcmp(argv[i], cmd_args[9]))) { // process mode
            g_inspection_mode = inspection_mode::im_process;
            selected_options |= 1 << 5;
        } else if ((0 == strcmp(argv[i], cmd_args[10])) || (0 == strcmp(argv[i], cmd_args[11]))) { // dump mode
            g_inspection_mode = inspection_mode::im_dump;
            selected_options |= 1 << 6;
        } else if ((argv[i] == strstr(argv[i], cmd_args[12])) || (argv[i] == strstr(argv[i], cmd_args[13]))) { // num alloc blocks
            const char* nb = (argv[i][1] == '-') ? (argv[i] + strlen(cmd_args[13])) : (argv[i] + strlen(cmd_args[12]));
            char* end = NULL;
            size_t arg_len = strlen(nb);
            DWORD nblocks = strtoul(nb, &end, is_hex(nb, arg_len) ? 16 : 10);
            if (nb != end) {
                nblocks = _max(1, _min(MAX_ALLOC_BLOCKS, nblocks));
                g_num_alloc_blocks = nblocks;
            }
            selected_options |= 1 << 7;
        } else if ((0 == strcmp(argv[i], cmd_args[14])) || (argv[i] == strstr(argv[i], cmd_args[15]))) { // disable page caching
            g_disable_page_caching = 1;
            selected_options |= 1 << 8;
        }
        else if ((0 == strcmp(argv[i], cmd_args[16])) || (argv[i] == strstr(argv[i], cmd_args[17]))) { // clear standby pages
#ifndef DISABLE_STANDBY_LIST_PURGE
            g_purge_standby_pages = 1;
            selected_options |= 1 << 9;
#endif // DISABLE_STANDBY_LIST_PURGE
        } else if ((0 == strcmp(argv[i], cmd_args[18])) || (argv[i] == strstr(argv[i], cmd_args[19]))) { // disable symbols
            g_disable_symbols = 1;
            selected_options |= 1 << 10;
        }
            // ...
    }
    constexpr uint32_t incompatible_mask = (1 << 5) | (1 << 6); // both -p and -d
    const bool incompatible_options = ((selected_options & incompatible_mask) == incompatible_mask);
    if ((g_inspection_mode == inspection_mode::im_none) || incompatible_options) {
        print_help();
        return false;
    }

    return true;
}

char* skip_to_args(char *cmd, size_t len) {
    bool found = false;
    size_t cur_len = 0;
    // skip whitespace
    while (((cur_len < len) && (cmd[cur_len] != 0))) {
        if (!isspace(cmd[cur_len])) {
            break;
        }
        cur_len++;
    }
    // skip to whitespace
    while (((cur_len < len) && (cmd[cur_len] != 0))) {
        if (isspace(cmd[cur_len])) {
            break;
        }
        cur_len++;
    }
    // skip whitespace
    while (((cur_len < len) && (cmd[cur_len] != 0))) {
        if (!isspace(cmd[cur_len])) {
            found = true;
            break;
        }
        cur_len++;
    }
    return found ? (cmd + cur_len) : nullptr;
}

void print_help_main_common() {
    puts("\n------------------------------------");
    puts("?\t\t\t - list commands (this message)");
    puts("/?\t\t\t - display search commands");
    puts(">?\t\t\t - display redirection commands");
    puts("%?\t\t\t - display calculation commands");
    puts("clear\t\t\t - clear screen");
    puts("i?\t\t\t - display inspection commands");
    puts("l?\t\t\t - display list commands");
    if (!g_disable_symbols) {
        puts("s?\t\t\t - display symbols commands");
    }
    puts("x?\t\t\t - display hexdump commands");
    puts("q | exit\t\t - quit program");
}

void print_help_search_common() {
    puts("\n------------------------------------");
    puts("/ <pattern>\t\t - search for a hex string");
    puts("/x <pattern>\t\t - search for a hex value (1-8 bytes wide)");
    puts("/a <pattern>\t\t - search for an ascii string");
    puts("*  Search commands have optional :i|:s|:o modifiers to limit the search to image, stack or other (e.g. /:s <pattern>)");
    puts("** Alternatively search could be ranged (e.g. /x@<start-address>:<length> <pattern>)");
}

void print_help_redirect_common() {
    puts("\n------------------------------------");
    puts("> <file-path>\t\t - redirect output to a file, overwrite data");
    puts(">a <file-path>\t\t - redirect output to a file, append data");
    puts("> stdout\t\t - redirect output to stdout");
}

void print_help_hexdump_common() {
    puts("\n------------------------------------");
    puts("xb@<address>:<N>\t - hexdump N bytes at address");
    puts("xw@<address>:<N>\t - hexdump N words at address");
    puts("xd@<address>:<N>\t - hexdump N dwords at address");
    puts("xq@<address>:<N>\t - hexdump N qwords at address");
    puts("* All hexdump commands can have an operation applied to the data.");
    puts("x(b|w|d|q)@<address>:<N>^<hex-string> - XOR hex-data with a hex-string");
    puts("x(b|w|d|q)@<address>:<N>&<hex-string> - AND hex-data with a hex-string");
}

void print_help_list_common() {
    puts("\n------------------------------------");
    puts("lM\t\t\t - list process modules");
    puts("lt\t\t\t - list process threads");
    puts("lm\t\t\t - list memory regions info");
    puts("lmc\t\t\t - list committed memory regions info");
    puts("*  Memory listing commands have optional :i|:s|:o modifiers to display only image, stack or other");
}

void print_help_inspect_common() {
    puts("\n------------------------------------");
    puts("im@<address>\t\t - inspect memory region");
    puts("iM <name>\t\t - inspect module");
    puts("it <tid>\t\t - inspect thread");
    puts("ii <file-path>\t\t - inspect image");
}

void print_help_calculate_common() {
    puts("\n------------------------------------");
    puts("%entropy@<address>:<size>\t\t - calculate entropy of a block");
    puts("%crc32c@<address>:<size>\t\t - calculate the crc32c of a block");
    puts("*  Block's size is clamped to the memory region size");
}

void print_help_symbols_common() {
    puts("\n------------------------------------");
    puts("s@<address>\t\t - resolve symbol at <address>");
    puts("sn <name>\t\t - resolve symbol by <name>");
    puts("sf\t\t\t - show next symbol");
    puts("sb\t\t\t - show previous symbol");
    puts("sp <path0;path1;..>\t - set symbol search paths (separated by ';'), override existing path");
    puts("spa <path0;path1;..>\t - set symbol search paths (separated by ';'), append to existing path");
    puts("sp\t\t\t - get symbol search paths");
}

inline search_scope_type set_scope(char ch) {
    search_scope_type scope_type;
    switch (ch) {
    case 'i':
        scope_type = search_scope_type::mrt_image;
        break;
    case 's':
        scope_type = search_scope_type::mrt_stack;
        break;
    case 'o':
        scope_type = search_scope_type::mrt_other;
        break;
    default:
        scope_type = mrt_none;
    }
    return scope_type;
}

static bool get_ptr(const char* cmd, void** p) {
    int res = sscanf_s(cmd, " @ %p", p);
    return res == 1;
}

static bool get_ptr_and_size(const char* cmd, void** p, int64_t* size) {
    int res = sscanf_s(cmd, "@%p:0x%llx", p, size); // "%*[^@]@%p:%lld"
    if (res < 2) {
        char ch = 0;
        int res = sscanf_s(cmd, "@%p:%llx%c", p, size, &ch);
        if ((res == 3) && (ch == ' ')) {
            res = sscanf_s(cmd, "@%p:%lld", p, size);
            if (res < 2) {
                return false;
            }
        } else if ((res != 3) || (ch != 'h')) {
            return false;
        }
    }
    return true;
}

static bool get_ptr_and_size_1(const char* cmd, void** p, int64_t* size) {
    int res = sscanf_s(cmd, " @ %p:0x%llx", p, size); // "%*[^@]@%p:%lld"
    if (res < 2) {
        char ch = 0;
        int res = sscanf_s(cmd, " @ %p:%llx%c", p, size, &ch);
        if ((res == 3) && (ch == ' ')) {
            res = sscanf_s(cmd, " @ %p:%lld", p, size);
            if (res < 2) {
                return false;
            }
        } else if ((res != 3) || (ch != 'h')) {
            return false;
        }
    }
    return true;
}

static bool get_ptr_and_size_2(const char* cmd, void** p, int64_t* size) {
    int res = sscanf_s(cmd, " @ %p:0x%llx", p, size); // "%*[^@]@%p:%lld"
    if (res < 2) {
        char ch = 0;
        int res = sscanf_s(cmd, " @ %p:%llx%c", p, size, &ch);
        if (res < 3 || ch == '^' || ch == '&') {
            res = sscanf_s(cmd, " @ %p:%lld", p, size);
            if (res < 2) {
                return false;
            }
        } else if (ch != 'h' && ch != '^' && ch != '&') {
            return false;
        }
    }
    return true;
}

static bool get_id(const char* cmd, DWORD* id) {
    int res = sscanf_s(cmd, " 0x%x", id);
    if (res < 1) {
        char ch = 0;
        int res = sscanf_s(cmd, " %x%c", id, &ch);
        if (res < 2) {
            res = sscanf_s(cmd, " %d", id);
            if (res < 1) {
                return false;
            }
        } else if (ch != 'h') {
            return false;
        }
    }
    return true;
}

inline const char* find_char(const char* buf, size_t len, char ch) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == ch) {
            return buf + i;
        }
    }
    return nullptr;
}

inline int skip_whitespace(const char* buf, size_t len) {
    for (int i = 0; i < len; i++) {
        if (buf[i + 1] != ' ') {
            return i + 1;
        }
    }
}

input_command parse_command_common(common_processing_context *ctx, search_data_info *data, char *pattern) {
    char* cmd = ctx->command;
    input_command command;
    memset(cmd, 0, sizeof(cmd));
    const char *res = gets_s(cmd, MAX_COMMAND_LEN + MAX_ARG_LEN);
    if (res == nullptr) {
        fprintf(stderr, "Empty input.\n");
        return c_continue;
    }
    if (cmd[0] == 0) {
        command = c_continue;
    } else if (((cmd[0] == 'q') && (cmd[1] == 0)) || (0 == strcmp(cmd, "exit"))) {
        puts("\n==== Exiting... ====");
        command = c_quit_program;
    } else if (cmd[0] == '?' && cmd[1] == 0) {
        command = c_help_main;
    } else if (cmd[0] == '>') {
        if (cmd[1] == '?') {
            return c_help_redirect;
        }
        const size_t cmd_len = strlen(cmd);
        const char* filepath = skip_to_args(cmd, cmd_len);
        if (filepath == nullptr) {
            fprintf(stderr, "File path missing.\n");
            return c_continue;
        }
        if ((0 == strcmp(filepath, "stdout"))) {
            redirect_output_to_stdout(ctx);
            ctx->rdata.redirect = false;
            ctx->rdata.append = false;
        } else {
            ctx->rdata.redirect = true;
            ctx->rdata.append = (cmd[1] == 'a');
            memset(ctx->rdata.filepath, 0, sizeof(ctx->rdata.filepath));
            memcpy_s(ctx->rdata.filepath, sizeof(ctx->rdata.filepath), filepath, strlen(filepath));
        }
        command = c_continue;
    } else if (0 == strcmp(cmd, "clear")) {
        clear_screen();
        command = c_continue;
    } else if (cmd[0] == '/') {
        if (cmd[1] == '?') {
            return c_help_search;
        }
        const int64_t arg_len = strlen(cmd);
        char* args = skip_to_args(cmd, arg_len);
        if (args == nullptr) {
            fprintf(stderr, "Pattern missing.\n");
            return c_continue;
        }
#if 0
        if (args[0] == '@') { // yes, this means that in "/a" mode the string can't start with '@'
            args = skip_to_args(args+1, arg_len);
            if (args == nullptr) {
                fprintf(stderr, "Pattern missing.\n");
                return c_continue;
            }
        }
#endif
        const int64_t pattern_len = arg_len - (ptrdiff_t)(args - cmd);

        int64_t cmd_length = arg_len - pattern_len;
        for (; cmd_length < arg_len; cmd_length--) {
            if (cmd[cmd_length - 1] != ' ') break;
        }

        // defaults
        input_type in_type = input_type::it_hex_string;
        search_scope_type scope_type = search_scope_type::mrt_all;
        command = c_search_pattern;
        // modifiers
        bool stop_parsing = false;
        for (uint64_t i = 1; (i < cmd_length) && !stop_parsing; i++) {
            switch (cmd[i]) {
            case 'x':
                in_type = input_type::it_hex_value;
                break;
            case 'a':
                in_type = input_type::it_ascii_string;
                break;
            case ':':
                if (scope_type != search_scope_type::mrt_all) {
                    fprintf(stderr, "Scoped search and ranged search are incompatible.\n");
                    return c_continue;
                }
                if ((i + 1) < cmd_length) {
                    scope_type = set_scope(cmd[i + 1]);
                    if (scope_type == search_scope_type::mrt_none) {
                        puts(unknown_command);
                        return c_continue;
                    }
                } else {
                    puts(unknown_command);
                    return c_continue;
                }
                stop_parsing = true;
                break;
            case 'r':
                in_type = input_type::it_hex_value; // temp
                command = c_search_pattern_in_registers;
                break;
            case ' ':
                if (((i + 1) >= cmd_length) || (cmd[i + 1] != '@')) {
                    puts(unknown_command);
                    return c_continue;
                }
                break;
            case '@': {
                if (scope_type != search_scope_type::mrt_all) {
                    fprintf(stderr, "Ranged search incompatible with i|s|h modifiers.\n");
                    return c_continue;
                }

                int64_t size = 0;
                void* p = nullptr;
                if (!get_ptr_and_size(cmd + i, &p, &size)) {
                    fprintf(stderr, error_parsing_the_input);
                    return c_continue;
                }
                if ((size > MAX_RANGE_LENGTH) || (size <= 0)) {
                    fprintf(stderr, "Invalid number of bytes to display. The limit is 0x%x\n", MAX_BYTE_TO_HEXDUMP);
                    return c_continue;
                }
                ctx->pdata.range.start = (const char*)p;
                ctx->pdata.range.length = size;
                scope_type = search_scope_type::mrt_range;
                stop_parsing = true;
                break;
            }
            default:
                fprintf(stderr, unknown_command);
                return c_continue;
            }
        }

        if (command == c_search_pattern_in_registers) {
            if ((in_type != input_type::it_hex_value) || (scope_type != search_scope_type::mrt_all)) {
                fprintf(stderr, unknown_command);
                return c_continue;
            }
        }

        ctx->pdata.scope_type = scope_type;
        memset(pattern, 0, MAX_PATTERN_LEN);
        memcpy(pattern, args, pattern_len);
        data->pdata.pattern_len = (int64_t)pattern_len;

        parse_input(pattern, data, in_type);
        if (data->type == it_error_type) {
            fprintf(stderr, "Error parsing the pattern. Does it match the command?\n");
            command = c_continue;
        } else {
            ctx->pdata.pattern = data->pdata.pattern;
            ctx->pdata.pattern_len = data->pdata.pattern_len;
        }
    } else if (cmd[0] == 'x') {
        if (cmd[1] == '?') {
            return c_help_hexdump;
        }
        hexdump_mode mode;
        if (cmd[1] == 'b') {
            mode = hexdump_mode::hm_bytes;
        } else if (cmd[1] == 'w') {
            mode = hexdump_mode::hm_words;
        } else if (cmd[1] == 'd') {
            mode = hexdump_mode::hm_dwords;
        } else if (cmd[1] == 'q') {
            mode = hexdump_mode::hm_qwords;
        } else {
            fprintf(stderr, unknown_command);
            return c_continue;
        }

        int64_t size = 0; 
        void *p = nullptr;
        if (!get_ptr_and_size_2(cmd + 2, &p, &size)) {
            fprintf(stderr, error_parsing_the_input);
            return c_continue;
        }
        if (((size * mode) > MAX_BYTE_TO_HEXDUMP) || (size <= 0)) {
            fprintf(stderr, "Invalid number of bytes to display. The limit is 0x%x\n", MAX_BYTE_TO_HEXDUMP);
            return c_continue;
        }

        // search for an operation
        const int64_t cmd_len = strlen(cmd);
        int op_position = -1;
        hexdump_op op = hexdump_op::ho_none;
        for (int i = 2; i < cmd_len; i++) {
            if (cmd[i] == '^') {
                op_position = i;
                op = hexdump_op::ho_xor;
                break;
            } else if (cmd[i] == '&') {
                op_position = i;
                op = hexdump_op::ho_and;
                break;
            }
        }
        if (op != hexdump_op::ho_none) {
            int64_t arg_len = cmd_len - op_position;
            // skip whitespace if there is any
            op_position += skip_whitespace(cmd + op_position, arg_len);
            arg_len = cmd_len - op_position;
            if (arg_len > MAX_OP_HEX_STRING_LEN) {
                fprintf(stderr, "Hexdump operation: hex string exceeds %d bytes.\n", MAX_OP_HEX_STRING_LEN / 2);
                return c_continue;
            }
            search_data_info data;
            data.pdata.pattern_len = arg_len;
            memset(ctx->hdata.hex_op.hex_str, 0, sizeof(ctx->hdata.hex_op.hex_str));
            memcpy(ctx->hdata.hex_op.hex_str, cmd + op_position, arg_len);
            parse_input((char*)ctx->hdata.hex_op.hex_str, &data, input_type::it_hex_string);
            if (data.type == it_error_type) {
                fprintf(stderr, "Error parsing the operation hex string.\n");
                return c_continue;
            } else {
                ctx->hdata.hex_op.str_len = data.pdata.pattern_len;
            }
        }

        ctx->hdata.address = (uint8_t*)p;
        ctx->hdata.num_to_display = size;
        ctx->hdata.mode = mode;
        ctx->hdata.hex_op.op = op;

        command = c_print_hexdump;
    } else if (cmd[0] == 'i') {
        if (cmd[1] == '?') {
            return c_help_inspect;
        }
        switch (cmd[1]) {
        case 'm': {
            void* p = nullptr;
            if (!get_ptr(cmd + 2, &p)) {
                return c_not_set;
            }
            ctx->i_data.memory_address = (const char*)p;
            command = c_inspect_memory;
            break;
        }
        case 'i': // same code as 'M'
        case 'M': {
            memset(ctx->i_data.module_name, 0, sizeof(ctx->i_data.module_name));
#ifdef _UNICODE
            char buffer[MAX_PATH];
            memset(buffer, 0, sizeof(buffer));
#elif defined(_MBCS)
            static_assert(sizeof(ctx->i_data.module_name) == MAX_PATH, "Module name exceeds maximum size.");
            char* buffer = ctx->i_data.module_name;
#endif

            int res = sscanf_s(cmd + 2, " %s", buffer, MAX_PATH);
            if (res < 1) {
                fprintf(stderr, error_parsing_the_input);
                return c_continue;
            }
#ifdef _UNICODE
            const int wc_size = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, NULL, 0);
            if (wc_size && (wc_size <= _countof(ctx->i_data.module_name))) {
                int result = MultiByteToWideChar(CP_UTF8, 0, buffer, -1, ctx->i_data.module_name, wc_size);
                if (result == 0) {
                    fprintf(stderr, "Error converting to wide character string: %s\n", buffer);
                    return c_continue;
                }
            } else {
                fprintf(stderr, "Module name exceeds maximum length: %s\n", buffer);
                return c_continue;
            }
#endif
            if (cmd[1] == 'M') {
                command = c_inspect_module;
            } else { // if cmd[1] == 'i'
                command = c_inspect_image;
            }

            break;
        }
        case 't': {
            if (!get_id(cmd + 2, &ctx->i_data.tid)) {
                fprintf(stderr, error_parsing_the_input);
                return c_continue;
            }
            command = c_inspect_thread;
            break;
        }
        default:
            fprintf(stderr, unknown_command);
            return c_continue;
        }
    } else if (cmd[0] == 'l') {
        if (cmd[1] == '?') {
            return c_help_list;
        }
        if (cmd[1] == 'M' && cmd[2] == 0) {
            command = c_list_modules;
        } else if (cmd[1] == 't') {
            if (cmd[2] == 0) {
                command = c_list_threads;
            } else if (cmd[2] == 'r') {
                command = c_list_thread_registers;
            } else {
                command = c_not_set;
            }
        } else if (cmd[1] == 'm') {
            if (cmd[2] == 'd' && cmd[3] == 0) {
                command = c_list_dump_memory_regions;
            } else {
                const size_t cmd_length = strlen(cmd);
                // defaults
                command = c_list_memory_regions_info;
                search_scope_type scope_type = search_scope_type::mrt_all;
                bool stop_parsing = false;
                for (int i = 2; (i < cmd_length) && !stop_parsing; i++) {
                    switch (cmd[i]) {
                    case 'c':
                        command = c_list_memory_regions_info_committed;
                        break;
                    case ':': {
                        if ((i + 1) < cmd_length) {
                            scope_type = set_scope(cmd[i + 1]);
                            if (scope_type == search_scope_type::mrt_none) {
                                fprintf(stderr, unknown_command);
                                return c_continue;
                            }
                        }
                        stop_parsing = true;
                        break;
                    }
                    default:
                        return c_not_set;
                    }
                }
                ctx->pdata.scope_type = scope_type;

            }
        } else if (cmd[1] == 'h' && cmd[2] == 0) {
            command = c_list_handles;
        } else {
            command = c_not_set;
        }
    }
    else if (cmd[0] == '%') {
        if (cmd[1] == '?') {
            return c_help_calculate;
        }
        const char* entropy = "entropy"; constexpr size_t entropy_sz = 7;
        const char* crc32c = "crc32c"; constexpr size_t crc32c_sz = 6;

        calculate_op op = calculate_op::co_none;
        size_t command_len = strlen(cmd);
        const char* args = cmd;
        const int args_offset = skip_whitespace(args, command_len - ptrdiff_t(args - cmd));
        args += args_offset;
        if (0 == memcmp(args, entropy, entropy_sz)) {
            args += entropy_sz;
            op = calculate_op::co_entropy;
        }
        else if (0 == memcmp(args, crc32c, crc32c_sz)) {
            args += crc32c_sz;
            op = calculate_op::co_crc32c;
        }
        else {
            fprintf(stderr, unknown_command);
            return c_continue;
        }
        void* p = nullptr;
        int64_t size = 0;
        if (!get_ptr_and_size_1(args, &p, &size)) {
            fprintf(stderr, error_parsing_the_input);
            return c_continue;
        }

        if (size <= 0 || size > MAX_CALCULATION_BLOCK_SIZE) {
            fprintf(stderr, "Block size exceed maximum size: 0x%llx", MAX_CALCULATION_BLOCK_SIZE);
            return c_continue;
        }

        ctx->cdata.address = (const uint8_t*)p;
        ctx->cdata.size = size;
        ctx->cdata.op = op;
        command = c_calculate;
    } else if (cmd[0] == 's') {
        if (g_disable_symbols) {
            fprintf(stderr, unknown_command);
            return c_continue;
        }
        if (cmd[1] == '?') {
            return c_help_symbols;
        }

        if (cmd[1] == 'p') {
            if (cmd[2] == 0) {
                command = c_symbol_get_path;
            } else {
                const bool append = cmd[2] == 'a';
                const size_t cmd_len = strlen(cmd);
                const char* paths = skip_to_args(cmd, cmd_len);
                if (cmd_len <= ptrdiff_t(paths - cmd)) {
                    fprintf(stderr, error_parsing_the_input);
                    return c_continue;
                }
                constexpr size_t max_path_len = sizeof(ctx->sym_ctx.paths);
                const size_t new_path_len = strlen(paths);
                if (new_path_len > max_path_len) {
                    fprintf(stderr, max_path_len_error, max_path_len);
                }
                strcpy_s(ctx->sym_ctx.paths, max_path_len, paths);
                ctx->sym_ctx.append_path = append;
                command = c_symbol_set_path;
            }
        } else if (cmd[1] == '@' || cmd[1] == ' ') {
            void* p = nullptr;
            if (!get_ptr(cmd + 1, &p)) {
                return c_continue;
            }

            ctx->sym_ctx.symbol_info->Address = (DWORD64)p;
            command = c_symbol_resolve_at_address;
        } else if (cmd[1] == 'n') {
            const size_t cmd_len = strlen(cmd);
            size_t name_offset = 2;
            name_offset += skip_whitespace(cmd + name_offset, cmd_len);
            if (name_offset > cmd_len) {
                fprintf(stderr, error_parsing_the_input);
                return c_continue;
            }
            memset(ctx->sym_ctx.symbol_info->Name, 0, MAX_SYM_NAME * sizeof(TCHAR));
            memcpy(ctx->sym_ctx.symbol_info->Name, cmd + name_offset, cmd_len - name_offset);
            command = c_symbol_resolve_by_name;
        } else if (cmd[1] == 'f') {
            command = c_symbol_resolve_fwd;
        } else if (cmd[1] == 'b') {
            command = c_symbol_resolve_bwd;
        } else {
            fprintf(stderr, unknown_command);
            return c_continue;
        }

    } else {
        command = c_not_set;
    }

    return command;
}

uint64_t prepare_matches(const common_processing_context* ctx, std::vector<search_match>& matches) {
    uint64_t num_matches = matches.size();

    if (!num_matches) {
        puts("*** No matches found. ***");
        return 0;
    }

    if (too_many_results(num_matches, output_redirected(ctx))) {
        return 0;
    }

    std::sort(matches.begin(), matches.end(), search_match_less);
    matches.erase(std::unique(matches.begin(), matches.end(),
        [](const search_match& a, const search_match& b) { return a.match_address == b.match_address; }), matches.end());

    return matches.size();
}

void print_hexdump(const hexdump_data& hdata, const uint8_t* bytes, size_t length) {
    printf("    - offset -      ");
    const uint8_t* address = hdata.address;
    const size_t size_bytes = length;
    const size_t size = size_bytes / hdata.mode;
    constexpr int bytes_in_row = 0x10;
    const int num_cols = bytes_in_row / hdata.mode;
    switch (hdata.mode) {
    case hm_bytes: {
        for (int i = 0; i < num_cols; i++) {
            printf("%02X ", ((uint32_t)address + i) & 0xFF);
        }
        printf(" ");
        for (int i = 0; i < num_cols; i++) {
            printf("%1X", ((uint32_t)address + i) & 0x0F);
        }
        puts("");
        size_t byte_id = 0;
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += bytes_in_row) {
            printf("0x%p  ", address);
            address += bytes_in_row;
            const size_t _sz = _min(num_cols, (size - byte_id));
            for (int j = 0; j < _sz; j++) {
                printf("%02x ", (uint8_t)bytes[byte_id+j]);
            }
            for (int j = _sz; j < num_cols; j++) {
                printf("   ");
            }
            printf(" ");
            for (int j = 0; j < _sz; j++) {
                char ch = (char)bytes[byte_id + j];
                if ((ch >= '!') && (ch <= '~')) {
                    printf("%c", (char)bytes[byte_id + j]);
                } else {
                    printf(".");
                }
            }
            puts("");
        }
        break;
    }
    case hm_words: {
        puts("");
        size_t byte_id = 0;
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += bytes_in_row) {
            printf("0x%p  ", address);
            address += bytes_in_row;
            const size_t _sz = _min(bytes_in_row, (size_bytes - byte_id));
            for (int j = 0; j < _sz; j+=sizeof(uint16_t)) {
                printf("0x%04x ", *(uint16_t*)&bytes[byte_id + j]);
            }
            puts("");
        }
        break;
    }
    case hm_dwords: {
        puts("");
        size_t byte_id = 0;
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += bytes_in_row) {
            printf("0x%p  ", address);
            address += bytes_in_row;
            const size_t _sz = _min(bytes_in_row, (size_bytes - byte_id));
            for (int j = 0; j < _sz; j += sizeof(uint32_t)) {
                printf("0x%08x ", *(uint32_t*)&bytes[byte_id + j]);
            }
            puts("");
        }
        break;
    }
    case hm_qwords: {
        puts("");
        size_t byte_id = 0;
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += bytes_in_row) {
            printf("0x%p  ", address);
            address += bytes_in_row;
            const size_t _sz = _min(bytes_in_row, (size_bytes - byte_id));
            for (int j = 0; j < _sz; j += sizeof(uint64_t)) {
                printf("0x%016llx ", *(uint64_t*)&bytes[byte_id + j]);
            }
            puts("");
        }
        break;
    }
    default:
        break;
    }
    puts("");
}

static void clear_screen() {
    wprintf(L"\x1b[2J \x1b[3J \x1b[0;0H");
}

void try_redirect_output_to_file(common_processing_context* ctx) {
    if (!output_redirected(ctx)) {
        return;
    }

    if (ctx->rdata.file) {
        fflush(ctx->rdata.file);
        fclose(ctx->rdata.file);
        ctx->rdata.file = nullptr;
    }
    if (0 != freopen_s(&ctx->rdata.file, ctx->rdata.filepath, ctx->rdata.append ? "a" : "w", stdout)) {
        fprintf(stderr, "Failed redirecting the output to the file.\n");
        ctx->rdata.redirect = false;
        return;
    }

    ctx->rdata.append = true;
}

void redirect_output_to_stdout(common_processing_context* ctx) {
    if (!output_redirected(ctx)) {
        return;
    }

    if (ctx->rdata.file) {
        fflush(ctx->rdata.file);
        fclose(ctx->rdata.file);
        ctx->rdata.file = nullptr;
    }

    FILE* console = nullptr;
    if (0 != freopen_s(&console, "CONOUT$", "w", stdout)) {
        fprintf(stderr, "*** Failed redirecting the output to stdout.\n");
    }
}

static void print_section_headers(PIMAGE_SECTION_HEADER section_headers, WORD number_of_sections) {
    printf("\nIMAGE_SECTION_HEADER\n");
    for (int i = 0; i < number_of_sections; i++) {
        printf("Section %d:\n", i + 1);
        printf("  Name: %.8s\n", section_headers[i].Name);
        printf("  VirtualSize: 0x%X\n", section_headers[i].Misc.VirtualSize);
        printf("  VirtualAddress: 0x%X\n", section_headers[i].VirtualAddress);
        printf("  SizeOfRawData: 0x%X\n", section_headers[i].SizeOfRawData);
        printf("  PointerToRawData: 0x%X\n", section_headers[i].PointerToRawData);
        printf("  Characteristics: 0x%X\n", section_headers[i].Characteristics);
    }
}

void print_image_info(const common_processing_context* ctx) {
    HANDLE file_handle = CreateFile(ctx->i_data.module_name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening file: %lu\n", GetLastError());
        return;
    }
    
    HANDLE mapping_handle = CreateFileMapping(file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping_handle) {
        fprintf(stderr, "Error creating file mapping: %lu\n", GetLastError());
        CloseHandle(file_handle);
        return;
    }
    
    LPVOID base_address = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (!base_address) {
        fprintf(stderr, "Error mapping view of file: %lu\n", GetLastError());
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        return;
    }
    
    PIMAGE_NT_HEADERS nt_headers = ImageNtHeader(base_address);
    if (!nt_headers) {
        fprintf(stderr, "Invalid PE file\n");
        UnmapViewOfFile(base_address);
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        return;
    }
    
    printf("IMAGE_NT_HEADERS\n");
    printf("Signature: 0x%X\n", nt_headers->Signature);
    printf("FileHeader.Machine: 0x%X\n", nt_headers->FileHeader.Machine);
    printf("FileHeader.NumberOfSections: %d\n", nt_headers->FileHeader.NumberOfSections);
    printf("FileHeader.TimeDateStamp: 0x%X\n", nt_headers->FileHeader.TimeDateStamp);
    printf("FileHeader.PointerToSymbolTable: 0x%X\n", nt_headers->FileHeader.PointerToSymbolTable);
    printf("FileHeader.NumberOfSymbols: %d\n", nt_headers->FileHeader.NumberOfSymbols);
    printf("FileHeader.SizeOfOptionalHeader: %d\n", nt_headers->FileHeader.SizeOfOptionalHeader);
    printf("FileHeader.Characteristics: 0x%X\n", nt_headers->FileHeader.Characteristics);
    
    if (nt_headers->FileHeader.SizeOfOptionalHeader == 0) {
        fprintf(stderr, "No optional header present.\n");
        UnmapViewOfFile(base_address);
        CloseHandle(mapping_handle);
        CloseHandle(file_handle);
        return;
    }
    
    printf("\nIMAGE_OPTIONAL_HEADER\n");
    PIMAGE_OPTIONAL_HEADER optional_header = &nt_headers->OptionalHeader;
    printf("Magic: 0x%X\n", optional_header->Magic);
    printf("MajorLinkerVersion: %d\n", optional_header->MajorLinkerVersion);
    printf("MinorLinkerVersion: %d\n", optional_header->MinorLinkerVersion);
    printf("SizeOfCode: 0x%X\n", optional_header->SizeOfCode);
    printf("AddressOfEntryPoint: 0x%X\n", optional_header->AddressOfEntryPoint);
    printf("ImageBase: 0x%X\n", optional_header->ImageBase);
    printf("SectionAlignment: 0x%X\n", optional_header->SectionAlignment);
    printf("FileAlignment: 0x%X\n", optional_header->FileAlignment);
    
    PIMAGE_SECTION_HEADER section_headers = (PIMAGE_SECTION_HEADER)((DWORD_PTR)optional_header + nt_headers->FileHeader.SizeOfOptionalHeader);
    print_section_headers(section_headers, nt_headers->FileHeader.NumberOfSections);
    
    UnmapViewOfFile(base_address);
    CloseHandle(mapping_handle);
    CloseHandle(file_handle);
}

uint32_t compute_crc32c(const uint8_t* data, size_t length) {
    constexpr size_t chunk_size = sizeof(uint64_t);
    uint32_t crc = 0xFFFFFFFF;

    while (length >= chunk_size) {
        uint64_t chunk = *(const uint64_t*)data;

        crc = _mm_crc32_u64(crc, chunk);
        data += chunk_size;
        length -= chunk_size;
    }

    while (length > 0) {
        crc = _mm_crc32_u8(crc, *data);
        data++;
        length--;
    }

    return ~crc; // finalise the CRC by inverting all the bits
}

void data_block_calculate_common(calculate_data* cdata, uint8_t* bytes, size_t size) {
    if (cdata->op == calculate_op::co_entropy) {
        entropy_context e_ctx;
        entropy_init(&e_ctx);
        entropy_calculate_frequencies(&e_ctx, bytes, size);
        const double entropy = entropy_compute(&e_ctx, size);
        printf("Block Start: 0x%p, Size: 0x%llx, Entropy: %.2f\n", cdata->address, size, entropy);
    } else { // if ctx->common.cdata.op == calculate_op::co_crc32c
        const uint32_t crc = compute_crc32c(bytes, size);
        printf("Block Start: 0x%p, Size: 0x%llx, CRC32C: 0x%08x\n", cdata->address, size, crc);
    }
    puts("");
}

#include <stdio.h>
#include <windows.h> // Include for SYMBOL_INFO and related definitions

static void print_symbol_info_flags(const SYMBOL_INFO* symbol_info) {
    if (symbol_info == NULL) {
        printf("Invalid SYMBOL_INFO pointer.\n");
        return;
    }

    printf("Flags: 0x%08X\n", symbol_info->Flags);

    if (symbol_info->Flags & SYMFLAG_VALUEPRESENT) {
        printf("  - Value is present\n");
    }
    if (symbol_info->Flags & SYMFLAG_REGISTER) {
        printf("  - Symbol is a register\n");
    }
    if (symbol_info->Flags & SYMFLAG_REGREL) {
        printf("  - Symbol is register-relative\n");
    }
    if (symbol_info->Flags & SYMFLAG_FRAMEREL) {
        printf("  - Symbol is frame-relative\n");
    }
    if (symbol_info->Flags & SYMFLAG_PARAMETER) {
        printf("  - Symbol is a parameter\n");
    }
    if (symbol_info->Flags & SYMFLAG_LOCAL) {
        printf("  - Symbol is a local variable\n");
    }
    if (symbol_info->Flags & SYMFLAG_CONSTANT) {
        printf("  - Symbol is a constant\n");
    }
    if (symbol_info->Flags & SYMFLAG_EXPORT) {
        printf("  - Symbol is an exported function\n");
    }
    if (symbol_info->Flags & SYMFLAG_FORWARDER) {
        printf("  - Symbol is a forwarder\n");
    }
    if (symbol_info->Flags & SYMFLAG_FUNCTION) {
        printf("  - Symbol is a function\n");
    }
    if (symbol_info->Flags & SYMFLAG_VIRTUAL) {
        printf("  - Symbol is virtual\n");
    }
    if (symbol_info->Flags & SYMFLAG_THUNK) {
        printf("  - Symbol is a thunk\n");
    }
    if (symbol_info->Flags & SYMFLAG_TLSREL) {
        printf("  - Symbol is TLS-relative\n");
    }
    // ...
}


static void print_symbol_info(const SYMBOL_INFO* symbol_info) {
    printf("Symbol: %s\n", symbol_info->Name);
    printf("Size: 0x%llx\n", symbol_info->Size);
    printf("ModBase: 0x%016llx\n", symbol_info->ModBase);
    printf("Address: 0x%016llx\n", symbol_info->Address);
    print_symbol_info_flags(symbol_info);
    // ...
}

void symbol_find_at_address(common_processing_context* ctx) {
    if (!ctx->sym_ctx.ctx_initialized) {
        fprintf(stderr, "Symbols haven't been initialized.\n");
        return;
    }

    const DWORD64 address = ctx->sym_ctx.symbol_info->Address;
    PSYMBOL_INFO symbol_info = ctx->sym_ctx.symbol_info;

    symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol_info->MaxNameLen = MAX_SYM_NAME;

    DWORD64 displacement = 0;

    if (SymFromAddr(ctx->sym_ctx.process, address, &displacement, symbol_info)) {
        printf("Address: 0x%016llx\n", address);
        print_symbol_info(symbol_info);

        //if (SymGetTypeInfo(ctx->sym_ctx.process, symbol_info->TypeIndex, /*IMAGEHLP_SYMBOL_TYPE_INFO*/, /*PVOID*/)) {
        //
        //}

        ctx->sym_ctx.sym_initialized = true;
    } else {
        printf("Failed to resolve symbol for address 0x%016llx.\n", address);
        ctx->sym_ctx.sym_initialized = false;
    }
}

void symbol_find_by_name(common_processing_context* ctx) {
    if (!ctx->sym_ctx.ctx_initialized) {
        fprintf(stderr, "Symbols haven't been initialized.\n");
        return;
    }

    const PCSTR name = ctx->sym_ctx.symbol_info->Name;
    PSYMBOL_INFO symbol_info = ctx->sym_ctx.symbol_info;

    symbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol_info->MaxNameLen = MAX_SYM_NAME;

    if (SymFromName(ctx->sym_ctx.process, name, symbol_info)) {
        print_symbol_info(symbol_info);
        ctx->sym_ctx.sym_initialized = true;
    } else {
        printf("Failed to resolve symbol %s.\n", name);
        ctx->sym_ctx.sym_initialized = false;
    }
}

void symbol_find_next(common_processing_context* ctx) {
    if (!ctx->sym_ctx.ctx_initialized) {
        fprintf(stderr, "Symbols haven't been initialized.\n");
        return;
    }
    if (!ctx->sym_ctx.sym_initialized) {
        fprintf(stderr, "Current symbol haven't been set yet.\n");
        return;
    }
    PSYMBOL_INFO symbol_info = ctx->sym_ctx.symbol_info;
    if (SymNext(ctx->sym_ctx.process, symbol_info)) {
        print_symbol_info(symbol_info);
    } else {
        printf("Failed to resolve next symbol %s.\n");
    }
}

void symbol_find_prev(common_processing_context* ctx) {
    if (!ctx->sym_ctx.ctx_initialized) {
        fprintf(stderr, "Symbols haven't been initialized.\n");
        return;
    }
    if (!ctx->sym_ctx.sym_initialized) {
        fprintf(stderr, "Current symbol haven't been set yet.\n");
        return;
    }
    PSYMBOL_INFO symbol_info = ctx->sym_ctx.symbol_info;
    if (SymPrev(ctx->sym_ctx.process, symbol_info)) {
        print_symbol_info(symbol_info);
    } else {
        printf("Failed to resolve previous symbol %s.\n");
    }
}

void symbol_get_path(const common_processing_context* ctx) {
    if (!ctx->sym_ctx.ctx_initialized) {
        fprintf(stderr, "Symbols haven't been initialized.\n");
        return;
    }

    char search_path[SYMBOL_PATHS_SIZE];
    memset(search_path, 0, sizeof(search_path));
    if (!SymGetSearchPath(ctx->sym_ctx.process, search_path, sizeof(search_path))) {
        fprintf(stderr, "Failed to get the symbol search path.\n");
        return;
    }
    printf("Symbol search path: %s\n", search_path);
}

bool symbol_set_path_common(const common_processing_context* ctx) {
    if (!ctx->sym_ctx.ctx_initialized) {
        fprintf(stderr, "Symbols haven't been initialized.\n");
        return false;
    }

    const char* new_path = ctx->sym_ctx.paths;
    char search_path[SYMBOL_PATHS_SIZE];
    if (ctx->sym_ctx.append_path) {
        memset(search_path, 0, sizeof(search_path));
        if (!SymGetSearchPath(ctx->sym_ctx.process, search_path, sizeof(search_path))) {
            fprintf(stderr, "Failed to get the symbol search path.\n");
            return false;
        }
        size_t path_len = strlen(search_path);
        size_t new_path_len = strlen(new_path);
        if ((new_path_len + path_len + 1) >= SYMBOL_PATHS_SIZE) {
            fprintf(stderr, max_path_len_error, SYMBOL_PATHS_SIZE);
            if (path_len + 1 >= SYMBOL_PATHS_SIZE) {
                return false;
            }
        }
        search_path[path_len++] = ';';
        strcpy_s(search_path + path_len, SYMBOL_PATHS_SIZE - path_len, new_path);
        new_path = search_path;
    }

    if (!SymSetSearchPath(ctx->sym_ctx.process, new_path)) {
        fprintf(stderr, "Failed to set the symbol search path.\n");
    }
    return true;
}

#ifndef NDEBUG
void print_last_error_message() {
    DWORD error_code = GetLastError(); // Get the last error code
    if (error_code == 0) {
        fprintf(stderr, "No error.\n");
        return;
    }

    LPVOID error_message_buffer;
    DWORD format_result = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&error_message_buffer,
        0,
        NULL
    );

    if (format_result == 0) {
        fprintf(stderr, "Failed to format error message. Error code: %lu\n", error_code);
    } else {
        fwprintf(stderr, L"Error (%lu): %s\n", error_code, (LPTSTR)error_message_buffer);
        LocalFree(error_message_buffer);
    }
}
#endif // NDEBUG