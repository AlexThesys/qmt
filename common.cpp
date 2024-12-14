#include "common.h"

const char* page_state[] = { "MEM_COMMIT", "MEM_FREE", "MEM_RESERVE" };
const char* page_type[] = { "MEM_IMAGE", "MEM_MAPPED", "MEM_PRIVATE" };
const char* page_protect[] = { "PAGE_EXECUTE", "PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY", "PAGE_NOACCESS", "PAGE_READONLY",
                                    "PAGE_READWRITE", "PAGE_WRITECOPY", "PAGE_TARGETS_INVALID", "UNKNOWN" };

const char* unknown_command = "Unknown command.";
const char* command_not_implemented = "Command not implemented.";
static const char* cmd_args[] = { "-h", "--help", "-f", "--show-failed-readings", "-t=", "--threads=", "-v", "--version",
                                "-p", "--process", "-d", "--dump", "-b=", "--blocks=" };
static constexpr size_t cmd_args_size = _countof(cmd_args) / 2; // given that every option has a long and a short forms
static const char* program_version = "Version 0.3.0";
static const char* program_name = "Quick Memory Tools";

int g_max_threads = MAX_THREADS;
LONG64 g_num_alloc_blocks = DEFAULT_ALLOC_BLOCKS;
int g_show_failed_readings = 0;
inspection_mode g_inspection_mode = inspection_mode::im_none;

static DWORD clear_screen();

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

bool too_many_results(size_t num_lines, bool precise) {
    if (num_lines < TOO_MANY_RESULTS) {
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
        fprintf(stderr, "Pattern exceeded maximum size of %d. Exiting...", MAX_PATTERN_LEN);
        data->type = it_error_type;
        return;
    }

    switch (in_type) {
    case input_type::it_hex_string : {
        int64_t pattern_len = data->pdata.pattern_len;
        if (pattern_len <= 1) {
            puts("Hex string is shorter than 1 byte.");
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
            printf("Max supported hex value size: %d bytes!", (int)sizeof(uint64_t));
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
    puts("-t=<num_threads> || --threads=<num_threads>\t -- limit the number of OMP threads");
    puts("-b=<N> || --block_info=<N>\t\t\t\t -- alloc block_info size == (dwAllocationGranularity * N), N=[1-8]");
    puts("-f || --show-failed-readings\t\t\t -- show the regions, that failed to be read (process mode only)\n");
}

bool parse_cmd_args(int argc, const char** argv) {
    if (argc > (cmd_args_size + 1)) {
        puts("Too many arguments provided: some will be discarded.");
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
                g_max_threads = _min(num_threads, g_max_threads);
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

void print_help_common() {
    puts("\n********************************");
    puts("?\t\t\t - list commands (this message)");
    puts("/ <pattern>\t\t - search for a hex string");
    puts("/x <pattern>\t\t - search for a hex value (1-8 bytes wide)");
    puts("/a <pattern>\t\t - search for an ascii string");
    puts("All search commands have optional i|s|h modifiers to limit the search to image | stack | heap");
    puts("xb <N> @ <address>\t - hexdump N bytes at address");
    puts("xw <N> @ <address>\t - hexdump N words at address");
    puts("xd <N> @ <address>\t - hexdump N dwords at address");
    puts("xq <N> @ <address>\t - hexdump N qwords at address");
    puts("clear\t\t\t - clear screen");
    puts("q | exit\t\t - quit program");
    puts("lM\t\t\t - list process modules");
    puts("lt\t\t\t - list process threads");
}

input_command parse_command_common(common_processing_context *ctx, search_data_info *data, char* cmd, char *pattern) {
    input_command command;
    memset(cmd, 0, sizeof(cmd));
    const char *res = gets_s(cmd, MAX_COMMAND_LEN + MAX_ARG_LEN);
    if (res == nullptr) {
        puts("Empty input.");
        return c_continue;
    }
    if (cmd[0] == 0) {
        command = c_continue;
    } else if ((cmd[0] == 'q') || (cmd[0] == 'Q') || (0 == strcmp(cmd, "exit"))) {
        puts("\n==== Exiting... ====");
        command = c_quit_program;
    } else if (cmd[0] == '?') {
        command = c_help;
    } else if (0 == strcmp(cmd, "clear")) {
        clear_screen();
        command = c_continue;
    } else if (cmd[0] == '/') {
        constexpr int max_seach_cmd_len = 3;
        int cmd_length = 1;
        for (; cmd_length < max_seach_cmd_len; cmd_length++) {
            if (cmd[cmd_length] == ' ') break;
        }
        // defaults
        input_type in_type = input_type::it_hex_string;
        memory_region_type mem_type = memory_region_type::mrt_all;
        command = c_search_pattern;
        // modifiers
        for (int i = 1; i < cmd_length; i++) {
            switch (cmd[i]) {
            case 'x':
                in_type = input_type::it_hex_value;
                break;
            case 'a':
                in_type = input_type::it_ascii_string;
                break;
            case 'i':
                mem_type = memory_region_type::mrt_image;
                break;
            case 's':
                mem_type = memory_region_type::mrt_stack;
                break;
            case 'h':
                mem_type = memory_region_type::mrt_heap;
                break;
                break;
            case 'r':
                command = c_search_pattern_in_registers;
                break;
            default:
                puts(unknown_command);
                return c_continue;
            }
        }

        if (command == c_search_pattern_in_registers) {
            if ((in_type != input_type::it_hex_string) || (mem_type != memory_region_type::mrt_all)) {
                puts(unknown_command);
                return c_continue;
            }
        }

        ctx->pdata.mem_type = mem_type;
        memset(pattern, 0, MAX_PATTERN_LEN);
        size_t pattern_len = strlen(cmd);
        char* args = skip_to_args(cmd, pattern_len);
        if (args == nullptr) {
            puts("Pattern missing.");
            return c_continue;
        }
        pattern_len -= (ptrdiff_t)(args - cmd);
        memcpy(pattern, args, pattern_len);
        data->pdata.pattern_len = (int64_t)pattern_len;

        parse_input(pattern, data, in_type);
        if (data->type == it_error_type) {
            puts("Error parsing the pattern. Does it match the command?");
            command = c_continue;
        } else {
            ctx->pdata.pattern = data->pdata.pattern;
            ctx->pdata.pattern_len = data->pdata.pattern_len;
        }
    } else if (cmd[0] == 'x') {
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
            puts(unknown_command);
            return c_continue;
        }

        int size = 0; 
        void *p = nullptr;
        int res = sscanf_s(cmd, "%*s %d @ %p", &size, &p);
        if (res < 2) {
            res = sscanf_s(cmd, "%*s %x @ %p", &size, &p);
            if (res < 2) {
                puts("Error parsing the input;");
                return c_continue;
            }
        }
        if (((size * mode) > MAX_BYTE_TO_HEXDUMP) || (size <= 0)) {
            printf("Invalid number of bytes to display. The limit is 0x%x\n", MAX_BYTE_TO_HEXDUMP);
            return c_continue;
        }

        ctx->hdata.address = (uint8_t*)p;
        ctx->hdata.num_to_display = size;
        ctx->hdata.mode = mode;

        command = c_print_hexdump;
    } else {
        command = c_not_set;
    }

    return command;
}

uint64_t prepare_matches(std::vector<search_match>& matches) {
    uint64_t num_matches = matches.size();

    if (!num_matches) {
        puts("*** No matches found. ***");
        return 0;
    }

    if (too_many_results(num_matches)) {
        return 0;
    }

    std::sort(matches.begin(), matches.end(), search_match_less);
    matches.erase(std::unique(matches.begin(), matches.end(),
        [](const search_match& a, const search_match& b) { return a.match_address == b.match_address; }), matches.end());

    return matches.size();
}

void print_hexdump(const hexdump_data& hdata, const std::vector<uint8_t>& bytes) {
    printf("    - offset -      ");
    const uint8_t* address = hdata.address;
    const size_t size_bytes = bytes.size();
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
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += num_cols) {
            printf("0x%p  ", address);
            address += num_cols;
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
            address += num_cols;
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
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += num_cols) {
            printf("0x%p  ", address);
            address += num_cols;
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
        for (int i = 0, sz = ((size + num_cols - 1) / num_cols); i < sz; i++, byte_id += num_cols) {
            printf("0x%p  ", address);
            address += num_cols;
            const size_t _sz = _min(bytes_in_row, (size_bytes - byte_id));
            for (int j = 0; j < _sz; j += sizeof(uint64_t)) {
                printf("0x%016x ", *(uint64_t*)&bytes[byte_id + j]);
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

static DWORD clear_screen() {
    HANDLE h_stdout = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD mode = 0;
    if (!GetConsoleMode(h_stdout, &mode))
    {
        return ::GetLastError();
    }

    const DWORD original_mode = mode;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    if (!SetConsoleMode(h_stdout, mode))
    {
        return ::GetLastError();
    }

    DWORD written = 0;
    PCWSTR sequence = L"\x1b[2J \x1b[3J \x1b[0;0H";
    if (!WriteConsoleW(h_stdout, sequence, (DWORD)wcslen(sequence), &written, NULL))
    {
        SetConsoleMode(h_stdout, original_mode);
        return ::GetLastError();
    }

    SetConsoleMode(h_stdout, original_mode);

    return 0;
}