#include "dump_mem_tool.h"
#include "common.h"
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

struct module_data {
    LPWSTR name;
    char* base_of_image;
    uint64_t size_of_image;
};

struct thread_data {
    uint32_t tid;
    uint32_t priority_class;
    uint32_t priority;
    // padding
    //char* teb;
    char* stack_base;
    CONTEXT* context;
};

struct cpu_info_data {
    USHORT processor_architecture;
    // ...
};

struct dump_context {
    common_context common;
    HANDLE file_base;
    HANDLE file_mapping;
    std::vector<module_data> m_data;
    std::vector<thread_data> t_data;
    cpu_info_data cpu_info;
};

struct reg_search_result {
    uint64_t match;
    DWORD tid;
    union {
        DWORD data;
        char reg_name[4];
    };
};

static void get_system_info(dump_context* ctx);
static void gather_modules(dump_context* ctx);
static void gather_threads(dump_context* ctx);
static bool list_memory64_regions(const dump_context* ctx);
static bool list_memory_regions(const dump_context* ctx);
static void list_modules(const dump_context* ctx);
static void list_threads(const dump_context* ctx);
static void list_thread_registers(const dump_context* ctx);
static void list_memory_regions_info(const dump_context* ctx, bool show_commited);

static bool map_file(const char* dump_file_path, HANDLE* file_handle, HANDLE* file_mapping_handle, LPVOID* file_base) {
    *file_handle = CreateFileA(dump_file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*file_handle == INVALID_HANDLE_VALUE) {
        perror("Failed to open the file.\n");
        return false;
    }

    *file_mapping_handle = CreateFileMapping(*file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!*file_mapping_handle) {
        perror("Failed to create file mapping.\n");
        CloseHandle(*file_handle);
        return false;
    }

    *file_base = MapViewOfFile(*file_mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (!*file_base) {
        perror("Failed to map view of file.\n");
        CloseHandle(*file_mapping_handle);
        CloseHandle(*file_handle);
        return false;
    }

    MINIDUMP_HEADER* header = (MINIDUMP_HEADER*)*file_base;
    
    if (header->Signature != MINIDUMP_SIGNATURE) {
        puts("The provided file is not a crash dump! Exiting...");
        UnmapViewOfFile(*file_base);
        CloseHandle(*file_mapping_handle);
        CloseHandle(*file_handle);
        return false;
    }

    const bool is_full_dump = (header->Flags & MiniDumpWithFullMemory) != 0;
    if (!is_full_dump) {
        puts("Crash dump is not a full dump - no point analysing it. Exiting..");
        UnmapViewOfFile(*file_base);
        CloseHandle(*file_mapping_handle);
        CloseHandle(*file_handle);
        return false;
    }

    return true;
}

static bool remap_file(HANDLE file_mapping_handle, LPVOID* file_base) {
    UnmapViewOfFile(*file_base);
    *file_base = MapViewOfFile(file_mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (!*file_base) {
        perror("Failed to map view of file.\n");
        return false;
    }
    return true;
}

static void find_pattern(dump_context *ctx, const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors, const MINIDUMP_MEMORY64_LIST* memory_list) {
    puts("Searching crash dump memory...");
    puts("\n------------------------------------\n");
    
    SYSTEM_INFO sysinfo = { 0 };
    ::GetSystemInfo(&sysinfo);
    const DWORD alloc_granularity = sysinfo.dwAllocationGranularity;
    assert(is_pow_2(alloc_granularity));

    g_memory_usage_bytes = 0;

    const size_t num_regions = memory_list->NumberOfMemoryRanges;

    std::vector<std::vector<const char*>> match; match.resize(num_regions);
    std::vector<uint64_t> rva; rva.reserve(num_regions);
    std::vector<MINIDUMP_MEMORY_DESCRIPTOR64> info; info.reserve(num_regions);
    const LONG64 max_memory_usage = g_memory_limit;

    {
        size_t cumulative_offset = 0;
        for (ULONG i = 0; i < num_regions; ++i) {
            const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = memory_descriptors[i];
            const uint64_t memory_data = memory_list->BaseRva + cumulative_offset;
            SIZE_T memory_size = static_cast<SIZE_T>(mem_desc.DataSize);
            info.push_back(mem_desc);
            rva.push_back(memory_data);
            cumulative_offset += mem_desc.DataSize;
        }
        UnmapViewOfFile(ctx->file_base);
    }

    const char* pattern = ctx->common.pattern;
    const size_t pattern_len = ctx->common.pattern_len;
    const size_t extra_chunk = multiple_of_n(pattern_len, sizeof(__m128i));
    const size_t block_size = alloc_granularity;
    const size_t bytes_to_read_ideal = block_size + extra_chunk;

    const int num_threads = _min(num_regions, _min(g_max_omp_threads, omp_get_num_procs()));
    omp_set_num_threads(num_threads);
#pragma omp parallel for schedule(dynamic, 1) shared(match,rva,info)
    for (int64_t i = 0;  i < (int64_t)num_regions; i++) {
        const size_t region_size = info[i].DataSize;
        if (region_size < pattern_len) {
            continue;
        }
        const uint64_t offset = rva[i];
        uint64_t offset_aligned = offset & ~(alloc_granularity - 1);
        uint64_t reminder = offset - offset_aligned;
        size_t total_bytes_to_map = region_size + reminder;
        size_t bytes_offset = 0;

        while (total_bytes_to_map) {
            size_t bytes_to_map;
            if (total_bytes_to_map >= bytes_to_read_ideal) {
                bytes_to_map = bytes_to_read_ideal;
                total_bytes_to_map -= block_size;
            } else {
                bytes_to_map = total_bytes_to_map;
                total_bytes_to_map = 0;
            }
            size_t bytes_to_read = bytes_to_map - reminder;

            const DWORD high = (DWORD)((offset_aligned >> 0x20) & 0xFFFFFFFF);
            const DWORD low = (DWORD)(offset_aligned & 0xFFFFFFFF);
            offset_aligned += block_size;

            {
                std::unique_lock<std::mutex> lk(g_mtx);
                while (true) {
                    g_cv.wait(lk, [max_memory_usage] { return (g_memory_usage_bytes < max_memory_usage); });
                    if (g_memory_usage_bytes < max_memory_usage) {
                        g_memory_usage_bytes += bytes_to_map;
                        break;
                    }
                }
            }

            HANDLE file_base = MapViewOfFile(ctx->file_mapping, FILE_MAP_READ, high, low, bytes_to_map);
            if (!file_base) {
                std::unique_lock<std::mutex> lk(g_mtx);
                g_memory_usage_bytes -= bytes_to_map;
                perror("Failed to map view of file.\n");
                continue;
            }

            const char* buffer = ((const char*)file_base + reminder);
            reminder = 0; // only needed for the first iteration
            
            if (!buffer) {
                UnmapViewOfFile(file_base);
                std::unique_lock<std::mutex> lk(g_mtx);
                g_memory_usage_bytes -= bytes_to_map;
                puts("Empty memory region!");
                continue;
            }


            if (bytes_to_read >= pattern_len) {
                const char* buffer_ptr = buffer;
                size_t buffer_size = bytes_to_read;

                while (buffer_size >= pattern_len) {
                    const char* old_buf_ptr = buffer_ptr;
                    buffer_ptr = (const char*)strstr_u8((const uint8_t*)buffer_ptr, buffer_size, (const uint8_t*)pattern, pattern_len);
                    if (!buffer_ptr) {
                        break;
                    }

                    const size_t buffer_offset = buffer_ptr - buffer;
                    match[i].push_back((const char*)(info[i].StartOfMemoryRange + buffer_offset));

                    buffer_ptr++;
                    buffer_size -= (buffer_ptr - old_buf_ptr);
                }
            }
            UnmapViewOfFile(file_base);
            {
                std::unique_lock<std::mutex> lk(g_mtx);
                g_memory_usage_bytes -= bytes_to_map;
            }
            g_cv.notify_all(); // permitted to be called concurrentely
        }
    }

    if (!remap_file(ctx->file_mapping,  &ctx->file_base)) {
        return;
    }
    gather_modules(ctx);
    gather_threads(ctx);

    size_t num_matches = 0;
    for (const auto& m : match) {
        num_matches += m.size();
    }
    if (!num_matches) {
        puts("*** No matches found. ***");
        return;
    }
    if (too_many_results(num_matches)) {
        return;
    }
    printf("*** Total number of matches: %llu ***\n\n", num_matches);
    
    for (size_t i = 0; i < num_regions; i++) {
        if (match[i].size()) {
            puts("------------------------------------\n");
            bool found_in_image = false;
            const MINIDUMP_MEMORY_DESCRIPTOR64& r_info = info[i];
            for (size_t m = 0, sz = ctx->m_data.size(); m < sz; m++) {
                const module_data& mdata = ctx->m_data[m];
                if (((ULONG64)mdata.base_of_image <= r_info.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (r_info.StartOfMemoryRange + r_info.DataSize))) {
                    wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                    found_in_image = true;
                    break;
                }
            }
            if (!found_in_image) {
                for (size_t t = 0, sz = ctx->t_data.size(); t < sz; t++) {
                    const thread_data& tdata = ctx->t_data[t];
                    if (((ULONG64)tdata.stack_base >= r_info.StartOfMemoryRange) && (tdata.context->Rsp <= (r_info.StartOfMemoryRange + r_info.DataSize))) {
                        wprintf((LPWSTR)L"Stack: Thread Id 0x%04x\n", tdata.tid);
                        break;
                    }
                }
            }
            printf("Start of Memory Region: 0x%p | Region Size: 0x%08llx\n\n",
                r_info.StartOfMemoryRange, r_info.DataSize);
            for (const char* m : match[i]) {
                printf("\tMatch at address: 0x%p\n", m);
            }
            puts("");
        }
    }
}

static void search_pattern_in_dump(dump_context *ctx) {
    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        perror("Failed to read Memory64ListStream.\n");
        return;
    }

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY64_LIST));
    find_pattern(ctx, memory_descriptors, memory_list);

}

static void search_pattern_in_registers(const dump_context *ctx) {
    std::vector<reg_search_result> matches;
    reg_search_result match;
    match.reg_name[0] = 'R';
    match.reg_name[3] = 0;
    const uint8_t* pattern = (const uint8_t*)ctx->common.pattern;
    size_t pattern_len = ctx->common.pattern_len;
    assert(pattern_len <= sizeof(uint64_t));
    for (const thread_data &data : ctx->t_data) {
        if (strstr_u8((const uint8_t*)&data.context->Rax, sizeof(data.context->Rax), pattern, pattern_len)) {
            match.match = data.context->Rax;
            match.tid = data.tid;
            match.reg_name[1] = 'A'; match.reg_name[2] = 'X';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rbx, sizeof(data.context->Rbx), pattern, pattern_len)) {
            match.match = data.context->Rbx;
            match.tid = data.tid;
            match.reg_name[1] = 'B'; match.reg_name[2] = 'X';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rcx, sizeof(data.context->Rcx), pattern, pattern_len)) {
            match.match = data.context->Rcx;
            match.tid = data.tid;
            match.reg_name[1] = 'C'; match.reg_name[2] = 'X';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rdx, sizeof(data.context->Rdx), pattern, pattern_len)) {
            match.match = data.context->Rdx;
            match.tid = data.tid;
            match.reg_name[1] = 'D'; match.reg_name[2] = 'X';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rdi, sizeof(data.context->Rdi), pattern, pattern_len)) {
            match.match = data.context->Rdi;
            match.tid = data.tid;
            match.reg_name[1] = 'D'; match.reg_name[2] = 'I';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rsi, sizeof(data.context->Rsi), pattern, pattern_len)) {
            match.match = data.context->Rsi;
            match.tid = data.tid;
            match.reg_name[1] = 'S'; match.reg_name[2] = 'I';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rsp, sizeof(data.context->Rsp), pattern, pattern_len)) {
            match.match = data.context->Rsp;
            match.tid = data.tid;
            match.reg_name[1] = 'S'; match.reg_name[2] = 'P';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rbp, sizeof(data.context->Rbp), pattern, pattern_len)) {
            match.match = data.context->Rbp;
            match.tid = data.tid;
            match.reg_name[1] = 'B'; match.reg_name[2] = 'P';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->Rip, sizeof(data.context->Rip), pattern, pattern_len)) {
            match.match = data.context->Rip;
            match.tid = data.tid;
            match.reg_name[1] = 'I'; match.reg_name[2] = 'P';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R8, sizeof(data.context->R8), pattern, pattern_len)) {
            match.match = data.context->R8;
            match.tid = data.tid;
            match.reg_name[1] = '8'; match.reg_name[2] = ' ';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R9, sizeof(data.context->R9), pattern, pattern_len)) {
            match.match = data.context->R9;
            match.tid = data.tid;
            match.reg_name[1] = '9'; match.reg_name[2] = ' ';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R10, sizeof(data.context->R10), pattern, pattern_len)) {
            match.match = data.context->R10;
            match.tid = data.tid;
            match.reg_name[1] = '1'; match.reg_name[2] = '0';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R11, sizeof(data.context->R11), pattern, pattern_len)) {
            match.match = data.context->R11;
            match.tid = data.tid;
            match.reg_name[1] = '1'; match.reg_name[2] = '1';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R12, sizeof(data.context->R12), pattern, pattern_len)) {
            match.match = data.context->R12;
            match.tid = data.tid;
            match.reg_name[1] = '1'; match.reg_name[2] = '2';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R13, sizeof(data.context->R13), pattern, pattern_len)) {
            match.match = data.context->R13;
            match.tid = data.tid;
            match.reg_name[1] = '1'; match.reg_name[2] = '3';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R14, sizeof(data.context->R14), pattern, pattern_len)) {
            match.match = data.context->R14;
            match.tid = data.tid;
            match.reg_name[1] = '1'; match.reg_name[2] = '4';
            matches.push_back(match);
        }
        if (strstr_u8((const uint8_t*)&data.context->R15, sizeof(data.context->R15), pattern, pattern_len)) {
            match.match = data.context->R15;
            match.tid = data.tid;
            match.reg_name[1] = '1'; match.reg_name[2] = '5';
            matches.push_back(match);
        }
    }

    const size_t num_matches = matches.size();
    if (!num_matches) {
        puts("*** No matches found. ***");
        return;
    }
    if (too_many_results(num_matches)) {
        return;
    }
    printf("*** Total number of matches: %llu ***\n", num_matches);

    DWORD tid_prev = (DWORD)(-1);
    for (const reg_search_result &res : matches) {
        if (tid_prev != res.tid) {
            puts("\n------------------------------------\n");
            printf("ThreadID: 0x%04x\n\n", res.tid);
            tid_prev = res.tid;
        }
        printf("\t%s: 0x%08llx\n", res.reg_name, res.match);
    }
    puts("");
}

static void print_help() {
    puts("--------------------------------");
    puts("/xr <pattern>\t\t - search for a hex value in registers");
    puts("ltr\t\t\t - list thread registers");
    puts("lm\t\t\t - list memory regions");
    puts("lmi\t\t\t - list memory regions info");
    puts("lmic\t\t\t - list committed memory regions info");
    puts("********************************\n");
}

static input_command parse_command(dump_context *ctx, search_data *data, char* cmd, char *pattern) {
    input_command command;
    if (cmd[0] == 'l') {
        if (cmd[1] == 'M') {
            command = c_list_modules;
        } else if (cmd[1] == 't') {
            if (cmd[2] == 0) {
                command = c_list_threads;
            } else if (cmd[2] =='r') {
                command = c_list_thread_registers;
            } else {
                puts(unknown_command);
                command = c_continue;
            }
        } else if (cmd[1] == 'm') {
            if (cmd[2] == 0) {
                command = c_list_memory_regions;
            } else if (cmd[2] == 'i') {
                if (cmd[3] == 0) {
                    command = c_list_memory_regions_info;
                } else if (cmd[3] == 'c') {
                    command = c_list_memory_regions_info_committed;
                } else {
                    puts(unknown_command);
                    command = c_continue;
                }
            } else {
                puts(unknown_command);
                command = c_continue;
            }
        } else {
            puts(unknown_command);
            command = c_continue;
        }
    } else {
        puts(unknown_command);
        command = c_continue;
    }
    puts("");

    return command;
}

static void execute_command(input_command cmd, const dump_context *ctx) {
    switch (cmd) {
    case c_help :
        print_help_common();
        print_help();
        break;
    case c_search_pattern :
        search_pattern_in_dump((dump_context*)ctx);
        break;
    case c_search_pattern_in_registers :
        search_pattern_in_registers(ctx);
        break;
    case c_list_memory_regions :
        if (!list_memory64_regions(ctx)) {
            list_memory_regions(ctx);
        }
        break;
    case c_list_memory_regions_info :
        list_memory_regions_info(ctx, false);
        break;
    case c_list_memory_regions_info_committed:
        list_memory_regions_info(ctx, true);
        break;
    case c_list_modules:
        list_modules(ctx);
        break;
    case c_list_threads:
        list_threads(ctx);
        break;
    case c_list_thread_registers:
        list_thread_registers(ctx);
        break;
    default :
        puts(unknown_command);
        break;
    }
    puts("====================================\n");
}

int run_dump_inspection() {
    char dump_file_path[MAX_PATH];
    memset(dump_file_path, 0, sizeof(dump_file_path));
    printf("\nProvide the path to the dmp file: ");
    gets_s(dump_file_path, sizeof(dump_file_path));
    puts("");

    HANDLE file_handle, file_mapping_handle, file_base;
    if (!map_file(dump_file_path, &file_handle, &file_mapping_handle, &file_base)) {
        return -1;
    }

    dump_context ctx = { { nullptr, 0 }, file_base, file_mapping_handle };
    get_system_info(&ctx);
    if (ctx.cpu_info.processor_architecture != PROCESSOR_ARCHITECTURE_AMD64) {
        puts("Only x86-64 architecture supported at the moment. Exiting..");
        return -1;
    }

    print_help_common();
    print_help();

    gather_modules(&ctx);
    gather_threads(&ctx);

    char pattern[MAX_PATTERN_LEN];
    char command[MAX_COMMAND_LEN + MAX_ARG_LEN];
    search_data data;

    while (1) {
        printf(">: ");
        input_command cmd = parse_command_common(&ctx.common, &data, command, pattern);
        if (cmd == input_command::c_not_set) {
            cmd = parse_command(&ctx, &data, command, pattern);
        } else {
            puts("");
        }
        if (cmd == c_quit_program) {
            break;
        } else if (cmd == c_continue) {
            continue;
        }
        execute_command(cmd, &ctx);
    }

    // epilogue
    UnmapViewOfFile(file_base);
    CloseHandle(file_mapping_handle);
    CloseHandle(file_handle);

    return 0;
}

static void get_system_info(dump_context* ctx) {
    MINIDUMP_SYSTEM_INFO* system_info = nullptr;
    ULONG stream_size = 0;
    ctx->cpu_info.processor_architecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
    if (!MiniDumpReadDumpStream(ctx->file_base, SystemInfoStream, nullptr, reinterpret_cast<void**>(&system_info), &stream_size)) {
        perror("Failed to read SystemInfoStream.\n");
    }
    ctx->cpu_info.processor_architecture = system_info->ProcessorArchitecture;
}

static void gather_modules(dump_context *ctx) {
    // Retrieve the Memory64ListStream
    MINIDUMP_MODULE_LIST* module_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, ModuleListStream, nullptr, reinterpret_cast<void**>(&module_list), &stream_size)) {
        perror("Failed to read ModuleListStream.\n");
        return;
    }

    const ULONG64 num_modules = module_list->NumberOfModules;
    const MINIDUMP_MODULE* modules = (MINIDUMP_MODULE*)((char*)(module_list)+sizeof(MINIDUMP_MODULE_LIST));
    ctx->m_data.resize(num_modules);

    for (ULONG i = 0; i < num_modules; i++) {
        const MINIDUMP_MODULE& module = modules[i];
        ctx->m_data[i] = { (WCHAR*)((char*)ctx->file_base + module.ModuleNameRva + sizeof(_MINIDUMP_STRING)), (char*)module.BaseOfImage, module.SizeOfImage };
    }
}

static void gather_threads(dump_context *ctx) {
    MINIDUMP_THREAD_LIST* thread_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, ThreadListStream, nullptr, reinterpret_cast<void**>(&thread_list), &stream_size)) {
        perror("Failed to read ThreadListStream.\n");
        return;
    }

    const ULONG32 num_threads = thread_list->NumberOfThreads;
    const MINIDUMP_THREAD* threads = (MINIDUMP_THREAD*)((char*)(thread_list)+sizeof(MINIDUMP_THREAD_LIST));
    ctx->t_data.resize(num_threads);

    for (ULONG i = 0; i < num_threads; i++) {
        const MINIDUMP_THREAD& thread = threads[i];
        ctx->t_data[i] = { thread.ThreadId, thread.PriorityClass, thread.Priority,/* (char*)thread.Teb,*/ 
                            (char*)(thread.Stack.StartOfMemoryRange+thread.Stack.Memory.DataSize), (CONTEXT*)((char*)ctx->file_base+thread.ThreadContext.Rva)};
    }
}

static bool list_memory64_regions(const dump_context* ctx) {

    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        perror("Failed to read Memory64ListStream.\n");
        return false;
    }

    // Parse and list memory regions
    const ULONG64 num_memory_regions =  memory_list->NumberOfMemoryRanges;
    if (too_many_results(num_memory_regions)) {
        return true;
    }

    printf("*** Number of Memory Regions: %llu ***\n\n", num_memory_regions);

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list) + sizeof(MINIDUMP_MEMORY64_LIST));

    ULONG prev_module = (ULONG)(-1);
    for (ULONG i = 0; i < num_memory_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = memory_descriptors[i];
        for (size_t m = 0, sz = ctx->m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx->m_data[m];
            if ((prev_module != m) && ((ULONG64)mdata.base_of_image <= mem_desc.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_desc.StartOfMemoryRange + mem_desc.DataSize))) {
                puts("------------------------------------\n");
                wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                prev_module = m;
                break;
            }
        }
        printf("Start Address: 0x%p | Size: 0x%08llx\n", mem_desc.StartOfMemoryRange, mem_desc.DataSize);
    }
    puts("");

    return true;
}

static bool list_memory_regions(const dump_context* ctx) {

    MINIDUMP_MEMORY_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, MemoryListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        perror("Failed to read MemoryListStream.\n");
        return false;
    }

    // Parse and list memory regions
    const ULONG64 num_memory_regions = memory_list->NumberOfMemoryRanges;
    if (too_many_results(num_memory_regions)) {
        return true;
    }

    printf("*** Number of Memory Regions: %llu ***\n\n", num_memory_regions);

    const MINIDUMP_MEMORY_DESCRIPTOR* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY_LIST));
    
    ULONG prev_module = (ULONG)(-1);
    for (ULONG i = 0; i < num_memory_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR& mem_desc = memory_descriptors[i];
        for (size_t m = 0, sz = ctx->m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx->m_data[m];
            if ((prev_module != m) && ((ULONG64)mdata.base_of_image <= mem_desc.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_desc.StartOfMemoryRange + mem_desc.Memory.DataSize))) {
                puts("------------------------------------\n");
                wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                prev_module = m;
                break;
            }
        }
        printf("Start Address: 0x%p\n", mem_desc.StartOfMemoryRange);
    }
    puts("");

    return true;
}

static void list_modules(const dump_context* ctx) {
    const ULONG64 num_modules = ctx->m_data.size();
    if (too_many_results(num_modules)) {
        return;
    }

    printf("*** Number of Modules: %llu ***\n\n", num_modules);

    for (ULONG i = 0; i < num_modules; i++) {
        const module_data& module = ctx->m_data[i];
        wprintf((LPWSTR)L"Module name: %s\n", module.name);
        printf("Base of image: 0x%p | Size of image: 0x%04llx\n\n", module.base_of_image, module.size_of_image);
    }
}

static void list_threads(const dump_context* ctx) {
    const ULONG64 num_threads = ctx->t_data.size();

    if (too_many_results(num_threads)) {
        return;
    }

    printf("*** Number of threads: %llu ***\n\n", num_threads);

    for (ULONG i = 0; i < num_threads; i++) {
        const thread_data& thread = ctx->t_data[i];
        printf("ThreadID: 0x%04x | Priority Class: 0x%04x | Priority: 0x%04x | Stack Base: 0x%p | RSP: 0x%p\n\n",
            thread.tid, thread.priority_class, thread.priority, (char*)thread.stack_base, (char*)thread.context->Rsp);
    }
}

static void list_thread_registers(const dump_context* ctx) {
    const ULONG64 num_threads = ctx->t_data.size();

    if (too_many_results(num_threads)) {
        return;
    }

    printf("*** Number of threads: %llu ***\n\n", num_threads);

    for (ULONG i = 0; i < num_threads; i++) {
        const thread_data& thread = ctx->t_data[i];
        printf("*** ThreadID: 0x%04x ***\nRAX: 0x%p RBX: 0x%p RCX: 0x%p RDI: 0x%p RSI: 0x%p\n", thread.tid,
            (char*)thread.context->Rax, (char*)thread.context->Rbx, (char*)thread.context->Rcx, (char*)thread.context->Rdx, 
            (char*)thread.context->Rdi, (char*)thread.context->Rsi);
        printf("RSP: 0x%p RBP: 0x%p RIP: 0x%p RFLAGS: 0x%04x\t\tMXCSR: 0x%04x\n",
            (char*)thread.context->Rsp, (char*)thread.context->Rbp, (char*)thread.context->Rip,
            (char*)thread.context->EFlags, (char*)thread.context->MxCsr);
        printf("R8:  0x%p R9:  0x%p R10: 0x%p R11: 0x%p\n",
            (char*)thread.context->R8, (char*)thread.context->R9, (char*)thread.context->R10, (char*)thread.context->R11);
        printf("R12: 0x%p R13: 0x%p R14: 0x%p R15: 0x%p\n",
            (char*)thread.context->R11, (char*)thread.context->R12, (char*)thread.context->R13, (char*)thread.context->R14);
        puts("\n----------------\n");
    }
}

static void list_memory_regions_info(const dump_context* ctx, bool show_commited) {
    MINIDUMP_MEMORY_INFO_LIST* memory_info_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, MemoryInfoListStream, nullptr, reinterpret_cast<void**>(&memory_info_list), &stream_size)) {
        perror("Failed to read MemoryInfoListStream.\n");
        return;
    }

    const ULONG64 num_entries = memory_info_list->NumberOfEntries;
    if (too_many_results(num_entries)) {
        return;
    }

    if (!show_commited) {
        printf("*** Number of Memory Info Entries: %llu ***\n\n", num_entries);
    }

    const MINIDUMP_MEMORY_INFO* memory_info = (MINIDUMP_MEMORY_INFO*)((char*)(memory_info_list) + sizeof(MINIDUMP_MEMORY_INFO_LIST));

    ULONG prev_module = (ULONG)(-1);
    for (ULONG i = 0; i < memory_info_list->NumberOfEntries; ++i) {
        const MINIDUMP_MEMORY_INFO& mem_info = memory_info[i];
        if (show_commited && (mem_info.State != MEM_COMMIT)) {
            continue;
        }
        for (size_t m = 0, sz = ctx->m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx->m_data[m];
            if ((prev_module != m) && ((ULONG64)mdata.base_of_image <= mem_info.BaseAddress) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_info.BaseAddress + mem_info.RegionSize))) {
                puts("------------------------------------\n");
                wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                prev_module = m;
                break;
            }
        }
        printf("Base Address: 0x%p | Size: 0x%08llx | State: %s\t | Protect: %s\t",
            memory_info[i].BaseAddress, memory_info[i].RegionSize, 
            get_page_state(mem_info.State), get_page_protect(mem_info.Protect));
        print_page_type(mem_info.Type);
    }
    puts("");
}