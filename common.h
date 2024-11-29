#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <assert.h>
#include <emmintrin.h>
#include <omp.h>
#include <mutex>
#include <condition_variable>
#include <vector> // temp

#define MAX_BUFFER_SIZE 0x1000
#define MAX_PATTERN_LEN 0x40
#define MAX_ARG_LEN MAX_PATTERN_LEN
#define MAX_COMMAND_LEN 0X10
#define MAX_OMP_THREADS 8
#define MAX_MEMORY_USAGE_IDEAL 0X40000000
#define TOO_MANY_RESULTS 0x400
#define MAX_MEM_LIM_GB 0x80

enum input_type {
    it_hex_string,
    it_hex_value,
    it_ascii_string,
    it_error_type,
};

enum input_command {
    c_help,
    c_search_pattern,
    c_list_pids,
    c_list_modules,
    c_list_threads,
    c_list_thread_registers,
    c_list_memory_regions,
    c_list_memory_regions_info,
    c_list_memory_regions_info_committed,
    c_travers_heap,
    c_travers_heap_calc_entropy,
    c_travers_heap_blocks,
    c_continue,
    c_quit_program,
    c_not_set,
};

enum inspection_mode {
    im_process,
    im_dump,
    im_none
};

struct common_context {
    const char* pattern;
    size_t pattern_len;
};

typedef struct search_data {
    input_type type;
    uint64_t value;
    const char* pattern;
    uint64_t pattern_len;
} search_data;

extern const char* page_state[];
extern const char* page_type[];
extern const char* page_protect[];

extern const char* unknown_command;

extern std::mutex g_mtx;
extern std::condition_variable g_cv;
extern LONG g_memory_usage_bytes;
extern int g_max_omp_threads;
extern int g_memory_limit;
extern int g_show_failed_readings;
extern inspection_mode g_inspection_mode;

#define _max(x,y) (x) > (y) ? (x) : (y)
#define _min(x,y) (x) < (y) ? (x) : (y)
#define step (sizeof(__m128i) / sizeof(uint8_t))

int check_architecture_rt();
const char* get_page_state(DWORD state);
void print_page_type(DWORD state);
const char* get_page_protect(DWORD state);
bool too_many_results(size_t num_lines);
const uint8_t* strstr_u8(const uint8_t* str, size_t str_sz, const uint8_t* substr, size_t substr_sz);
char* skip_to_args(char* cmd, size_t len);
bool parse_cmd_args(int argc, const char** argv);
void print_help_common();
input_command parse_command_common(common_context* ctx, search_data* data, char* cmd, char* pattern);

inline int is_hex(const char* pattern, size_t pattern_len) {
    return (((pattern_len > 2) && (pattern[pattern_len - 1] == 'h' || pattern[pattern_len - 1] == 'H'))
        || ((pattern_len > 3) && (pattern[0] == '0' && pattern[1] == 'x')));
}
