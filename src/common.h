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
#include "semaphore.h"

#ifdef TRACY_ENABLE
#include "Tracy.hpp"
#endif // TRACY_ENABLE

#define MAX_BUFFER_SIZE 0x1000
#define MAX_PATTERN_LEN 0x80
#define MAX_ARG_LEN MAX_PATTERN_LEN
#define MAX_COMMAND_LEN 0X40
#define MAX_THREAD_NUM 0x80
#define IDEAL_THREAD_NUM_DUMP 0X04
#define IDEAL_THREAD_NUM_DUMP_W_CACHING 0X08
#define INVALID_THREAD_NUM (-1)
#define TOO_MANY_RESULTS 0x400
#define DEFAULT_ALLOC_BLOCKS 0x04
#define MAX_ALLOC_BLOCKS 0x10
#define SEARCH_DATA_QUEUE_SIZE_POW2 0X04
#define MAX_BYTE_TO_HEXDUMP 0x10000
#define MAX_RANGE_LENGTH 0xf0000000
#define NUM_WAITING_DOTS 0x10
#define NEXT_DOT_INTERVAL 0x10
#define WAIT_FOR_MS 400
#define AVAIL_PHYS_MEM_FACTOR 0X04 // ?
#define INVALID_ID ((DWORD)(-1))

//#define DISABLE_STANDBY_LIST_PURGE

enum input_type {
    it_hex_string,
    it_hex_value,
    it_ascii_string,
    it_error_type,
};

enum search_scope_type {
    mrt_all = 0,
    mrt_image,
    mrt_stack,
    mrt_other,

    mrt_range,
};

enum input_command {
    c_help_main,
    c_help_search,
    c_help_redirect,
    c_help_list,
    c_help_info,
    c_help_hexdump,
    c_help_traverse_heap,
    c_help_commands_number,
    c_search_pattern,
    c_search_pattern_in_registers,
    c_list_pids,
    c_print_hexdump,
    c_list_modules,
    c_list_threads,
    c_list_thread_registers,
    c_list_memory_regions,
    c_list_memory_regions_info,
    c_list_memory_regions_info_committed,
    c_list_handles,
    c_inspect_memory,
    c_inspect_module,
    c_inspect_thread,
    c_print_info_thread_registers,
    c_travers_heap,
    c_travers_heap_calc_entropy,
    c_travers_heap_blocks,
    c_test_pid,
    c_continue,
    c_quit_program,
    c_not_set,
};

enum inspection_mode {
    im_process,
    im_dump,
    im_none
};

enum hexdump_mode {
    hm_bytes = 1,
    hm_words = 2,
    hm_dwords = 4,
    hm_qwords = 8
};

struct search_range {
    const char* start;
    uint64_t length;
};

struct pattern_data {
    const char* pattern;
    int64_t pattern_len;
    search_scope_type scope_type;
    search_range range;
};

struct hexdump_data {
    const uint8_t* address;
    size_t num_to_display;
    hexdump_mode mode;
};

struct redirection_data {
    FILE* file = nullptr;
    bool redirect = false;
    bool append = false;
    char filepath[MAX_PATH];
};

struct inspect_context {
    const char* memory_address;
    DWORD tid;
    wchar_t module_name[MAX_PATH];
};

struct common_processing_context {
    pattern_data pdata;
    hexdump_data hdata;
    redirection_data rdata;
    char* command = nullptr;
    inspect_context info_ctx{ nullptr, INVALID_ID };
};

struct search_data_info {
    input_type type;
    uint64_t value;
    pattern_data pdata;
};

struct search_match {
    uint64_t info_id;
    const char* match_address;
};

struct search_context_common {
    std::vector<search_match> matches;
    semaphore master_sem;
    semaphore_counting workers_sem;
    volatile int exit_workers;
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
extern int g_purge_standby_pages;
extern int g_disable_page_caching;

#define _max(x,y) (x) > (y) ? (x) : (y)
#define _min(x,y) (x) < (y) ? (x) : (y)

int check_architecture_rt();
const char* get_page_state(DWORD state);
void print_page_type(DWORD state);
const char* get_page_protect(DWORD state);
bool too_many_results(size_t num_lines, bool redirected, bool precise=true);
const uint8_t* strstr_u8(const uint8_t* str, size_t str_sz, const uint8_t* substr, size_t substr_sz);
char* skip_to_args(char* cmd, size_t len);
bool parse_cmd_args(int argc, const char** argv);
void print_help_main_common();
void print_help_search_common();
void print_help_redirect_common();
void print_help_hexdump_common();
void print_help_list_common();
void print_help_inspect_common();
input_command parse_command_common(common_processing_context* ctx, search_data_info* data, char* pattern);
uint64_t prepare_matches(const common_processing_context *ctx, std::vector<search_match>& matches);
void print_hexdump(const hexdump_data& hdata, const std::vector<uint8_t> &bytes);
void try_redirect_output_to_file(common_processing_context* ctx);
void redirect_output_to_stdout(common_processing_context* ctx);

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

inline uint64_t get_alloc_granularity() {
    SYSTEM_INFO sysinfo = { 0 };
    ::GetSystemInfo(&sysinfo);
    const DWORD alloc_granularity = sysinfo.dwAllocationGranularity;
    assert(is_pow_2(alloc_granularity));
    return (uint64_t)alloc_granularity;
}

inline bool get_available_phys_memory(DWORDLONG *total_pmem, DWORDLONG *available_pmem) {
    MEMORYSTATUSEX mem_info;
    mem_info.dwLength = sizeof(mem_info);
    if (GlobalMemoryStatusEx(&mem_info)) {
        *total_pmem = mem_info.ullTotalPhys;
        *available_pmem = mem_info.ullAvailPhys;
        return true;
    }
    return false;
}

inline bool output_redirected(const common_processing_context* ctx) {
    return ctx->rdata.redirect;
}

inline bool ranges_intersect(uint64_t a_start, uint64_t a_length, uint64_t b_start, uint64_t b_length) {
    const uint64_t a_end = a_start + a_length;
    const uint64_t b_end = b_start + b_length;

    return !(a_end < b_start || b_end < a_start);
}