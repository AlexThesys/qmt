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
#include <mutex>
#include <condition_variable>
#include <vector> // temp
#include <algorithm>

#include "circular_buffer.h"

#define MAX_BUFFER_SIZE 0x1000
#define MAX_PATTERN_LEN 0x40
#define MAX_ARG_LEN MAX_PATTERN_LEN
#define MAX_COMMAND_LEN 0X10
#define MAX_THREADS 0x10
#define TOO_MANY_RESULTS 0x400
#define MAX_MEM_LIM_GB 0x80
#define MAX_ALLOC_BLOCKS 0x08
#define SEARCH_DATA_QUEUE_SIZE_POW2 0X04

enum input_type {
    it_hex_string,
    it_hex_value,
    it_ascii_string,
    it_error_type,
};

enum input_command {
    c_help,
    c_search_pattern,
    c_search_pattern_in_registers,
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

typedef struct search_data_info {
    input_type type;
    uint64_t value;
    const char* pattern;
    uint64_t pattern_len;
} search_data_info;

struct search_match {
    uint64_t info_id;
    const char* match_address;
};

struct search_context_common {
    std::condition_variable master_cv;
    std::condition_variable workers_cv;
    std::vector<search_match> matches;
    std::mutex master_mtx;
    std::mutex workers_mtx;
    volatile BOOL exit_workers;
    spinlock matches_lock;
};

extern const char* page_state[];
extern const char* page_type[];
extern const char* page_protect[];

extern const char* unknown_command;
extern const char* command_not_implemented;

extern int g_max_threads;
extern LONG64 g_num_alloc_blocks;
extern int g_show_failed_readings;
extern inspection_mode g_inspection_mode;

#define _max(x,y) (x) > (y) ? (x) : (y)
#define _min(x,y) (x) < (y) ? (x) : (y)

int check_architecture_rt();
const char* get_page_state(DWORD state);
void print_page_type(DWORD state);
const char* get_page_protect(DWORD state);
bool too_many_results(size_t num_lines);
const uint8_t* strstr_u8(const uint8_t* str, size_t str_sz, const uint8_t* substr, size_t substr_sz);
char* skip_to_args(char* cmd, size_t len);
bool parse_cmd_args(int argc, const char** argv);
void print_help_common();
input_command parse_command_common(common_context* ctx, search_data_info* data, char* cmd, char* pattern);
uint64_t prepare_matches(std::vector<search_match>& matches);

inline int is_hex(const char* pattern, size_t pattern_len) {
    return (((pattern_len > 2) && (pattern[pattern_len - 1] == 'h' || pattern[pattern_len - 1] == 'H'))
        || ((pattern_len > 3) && (pattern[0] == '0' && pattern[1] == 'x')));
}

inline bool is_pow_2(uint64_t x)
{
    return (x & (x - 1)) == 0;
}

inline int multiple_of_n(int64_t val, int64_t n) {
    return ((val - 1) | (n - 1)) + 1;
}

inline bool search_match_less(const search_match& a, const search_match& b) {
    if (a.info_id < b.info_id) {
        return true;
    }
    if (a.info_id == b.info_id) {
        return (a.match_address < b.match_address);
    }
    return false;
}

inline DWORD get_alloc_granularity() {
    SYSTEM_INFO sysinfo = { 0 };
    ::GetSystemInfo(&sysinfo);
    const DWORD alloc_granularity = sysinfo.dwAllocationGranularity;
    assert(is_pow_2(alloc_granularity));
    return alloc_granularity;
}