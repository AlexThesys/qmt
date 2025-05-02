#include "common.h"

struct module_data {
    LPWSTR name;
    char* base_of_image;
    uint64_t size_of_image;
};

struct thread_info_dump {
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

struct cache_memory_regions_ctx {
    volatile int ready = 1;
    volatile int interrupt = 0;
};

struct dump_processing_context {
    common_processing_context common;
    HANDLE file_handle;
    HANDLE file_mapping;
    HANDLE file_base;
    std::vector<module_data> m_data;
    std::vector<thread_info_dump> t_data;
    cpu_info_data cpu_info;
    cache_memory_regions_ctx pages_caching_state;
};

struct reg_search_result {
    uint64_t match;
    DWORD tid;
    union {
        DWORD data;
        char reg_name[4];
    };
};

struct block_info_dump {
    size_t start_offset;
    size_t bytes_to_map;
    size_t bytes_to_read;
    DWORD low;
    DWORD high;
    uint32_t info_id;
};

struct search_context_dump {
    circular_buffer<block_info_dump, SEARCH_DATA_QUEUE_SIZE_POW2> block_info_queue;
    std::vector<MINIDUMP_MEMORY_DESCRIPTOR64> mem_info;
    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = nullptr; 
    const MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    dump_processing_context *ctx = nullptr;
    search_context_common common{};
};

static void get_system_info(dump_processing_context* ctx);
static void gather_modules(dump_processing_context* ctx);
static void gather_threads(dump_processing_context* ctx);
static bool list_memory64_regions(const dump_processing_context* ctx);
static bool list_memory_regions(const dump_processing_context* ctx);
static void list_modules(const dump_processing_context* ctx);
static void list_threads(const dump_processing_context* ctx);
static void list_thread_registers(const dump_processing_context* ctx);
static void list_memory_regions_info(const dump_processing_context* ctx, bool show_commited);
static void print_memory_info(const dump_processing_context* ctx);
static void print_module_info(const dump_processing_context* ctx);
static void print_thread_info(const dump_processing_context* ctx);
static void list_handle_descriptors(const dump_processing_context* ctx);
static bool init_symbols(dump_processing_context* ctx);
static void deinit_symbols(common_processing_context* ctx);
static void symbol_set_path(const dump_processing_context* ctx);
static bool is_drive_ssd(const char* file_path);
static void cache_memory_regions(dump_processing_context* ctx);
static void wait_for_memory_regions_caching(cache_memory_regions_ctx* ctx);
static void stop_memory_regions_caching(cache_memory_regions_ctx* ctx, std::thread& t);
static bool is_elevated();
static bool purge_standby_list();
static void data_block_calculate(dump_processing_context* ctx);

static bool map_file(const char* dump_file_path, HANDLE* file_handle, HANDLE* file_mapping_handle, LPVOID* file_base) {
    *file_handle = CreateFileA(dump_file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN /*FILE_ATTRIBUTE_NORMAL*/, NULL);
    if (*file_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "\nFailed to open the file.\n");
        return false;
    }

    *file_mapping_handle = CreateFileMapping(*file_handle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!*file_mapping_handle) {
        fprintf(stderr, "\nFailed to create file mapping.\n");
        CloseHandle(*file_handle);
        return false;
    }

    *file_base = MapViewOfFile(*file_mapping_handle, FILE_MAP_READ, 0, 0, 0);
    if (!*file_base) {
        fprintf(stderr, "\nFailed to map view of file.\n");
        CloseHandle(*file_mapping_handle);
        CloseHandle(*file_handle);
        return false;
    }

    MINIDUMP_HEADER* header = (MINIDUMP_HEADER*)*file_base;
    
    if (header->Signature != MINIDUMP_SIGNATURE) {
        fprintf(stderr, "The provided file is not a crash dump! Exiting...\n");
        UnmapViewOfFile(*file_base);
        CloseHandle(*file_mapping_handle);
        CloseHandle(*file_handle);
        return false;
    }

    const bool is_full_dump = (header->Flags & MiniDumpWithFullMemory) != 0;
    if (!is_full_dump) {
        fprintf(stderr, "Crash dump is not a full dump - no point analysing it. Exiting..\n");
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
        fprintf(stderr, "Failed to map view of file.\n");
        return false;
    }
    return true;
}

static void find_pattern(search_context_dump* search_ctx) {
    const char* pattern = search_ctx->ctx->common.pdata.pattern;
    const int64_t pattern_len = search_ctx->ctx->common.pdata.pattern_len;
    auto& matches = search_ctx->common.matches;
    auto& mem_snapshots = search_ctx->common.mem_snapshots;
    auto& mem_info = search_ctx->mem_info;
    auto& block_info_queue = search_ctx->block_info_queue;
    auto& exit_workers = search_ctx->common.exit_workers;

    const bool ranged_search = search_ctx->ctx->common.pdata.scope_type == search_scope_type::mrt_range;
    const char* range_start = search_ctx->ctx->common.pdata.range.start;
    const char* range_end = search_ctx->ctx->common.pdata.range.start + search_ctx->ctx->common.pdata.range.length;

    block_info_dump block;
    while (1) {
        int exit = false;
        while (!block_info_queue.try_pop(block)) {
            if (search_ctx->common.exit_workers) {
                exit = true;
                break;
            }
            search_ctx->common.workers_sem.wait();
        }
        search_ctx->common.master_sem.signal();
        if (exit && !block_info_queue.try_pop(block)) {
            break;
        }

        const size_t bytes_to_map = block.bytes_to_map;
        const size_t bytes_to_read = block.bytes_to_read;
        const size_t start_offset = block.start_offset;
        const DWORD low = block.low;
        const DWORD high = block.high;
        const size_t reminder = bytes_to_map - bytes_to_read;
        const size_t info_id = block.info_id;
        const MINIDUMP_MEMORY_DESCRIPTOR64& r_info = mem_info[info_id];

        HANDLE file_base = MapViewOfFile(search_ctx->ctx->file_mapping, FILE_MAP_READ, high, low, bytes_to_map);

        if (!file_base) {
            puts("Failed to map view of file.");
            continue;
        }

        const char* buffer = ((const char*)file_base + reminder);

        if (!buffer) {
            UnmapViewOfFile(file_base);
            puts("Empty memory region!");
            continue;
        }

        if ((int64_t)bytes_to_read >= pattern_len) {
            const char* buffer_ptr = buffer;
            int64_t buffer_size = (int64_t)bytes_to_read;

            while (buffer_size >= pattern_len) {
                const char* old_buf_ptr = buffer_ptr;
                buffer_ptr = (const char*)strstr_u8((const uint8_t*)buffer_ptr, buffer_size, (const uint8_t*)pattern, pattern_len);
                if (!buffer_ptr) {
                    break;
                }

                const ptrdiff_t buffer_offset = buffer_ptr - buffer;
                const char* match = (const char*)(r_info.StartOfMemoryRange + buffer_offset + start_offset);
                if (!ranged_search || ((match >= range_start) && ((match < range_end)))) {
                    mem_snapshot snapshot;
                    const int64_t size = _min(sizeof(snapshot.data), buffer_size);
                    snapshot.size = (uint32_t)size;
                    memcpy(&snapshot.data, buffer_ptr, size);
                    search_ctx->common.matches_lock.lock();
                    const uint32_t current_id = (uint32_t)mem_snapshots.size();
                    matches.push_back(search_match{ block.info_id, current_id, match });
                    mem_snapshots.push_back(snapshot);
                    search_ctx->common.matches_lock.unlock();
                }
                buffer_ptr++;
                buffer_size -= (buffer_ptr - old_buf_ptr);
            }
        }
        UnmapViewOfFile(file_base);
    }
}

static bool identify_memory_region_type(search_scope_type scope_type, const MINIDUMP_MEMORY_DESCRIPTOR64 &info, const dump_processing_context &ctx) {
    if (scope_type == search_scope_type::mrt_image) {
        for (size_t m = 0, sz = ctx.m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx.m_data[m];
            if (((ULONG64)mdata.base_of_image <= info.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (info.StartOfMemoryRange + info.DataSize))) {
                return true;
            }
        }
    } else if (scope_type == search_scope_type::mrt_stack) {
        for (size_t t = 0, sz = ctx.t_data.size(); t < sz; t++) {
            const thread_info_dump& tdata = ctx.t_data[t];
            if (((ULONG64)tdata.stack_base >= info.StartOfMemoryRange) && (tdata.context->Rsp <= (info.StartOfMemoryRange + info.DataSize))) {
                return true;
            }
        }
    } else if (scope_type == search_scope_type::mrt_other) {
        for (size_t t = 0, sz = ctx.t_data.size(); t < sz; t++) {
            const thread_info_dump& tdata = ctx.t_data[t];
            if (((ULONG64)tdata.stack_base >= info.StartOfMemoryRange) && (tdata.context->Rsp <= (info.StartOfMemoryRange + info.DataSize))) {
                return false;
            }
        }
        for (size_t m = 0, sz = ctx.m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx.m_data[m];
            if (((ULONG64)mdata.base_of_image <= info.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (info.StartOfMemoryRange + info.DataSize))) {
                return false;
            }
        }
        return true;
    }
    return false;
}

static bool identify_memory_region_type(search_scope_type scope_type, const MINIDUMP_MEMORY_INFO& info, const dump_processing_context &ctx) {
    if (scope_type == search_scope_type::mrt_image) {
        for (size_t m = 0, sz = ctx.m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx.m_data[m];
            if (((ULONG64)mdata.base_of_image <= info.BaseAddress) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (info.BaseAddress + info.RegionSize))) {
                return true;
            }
        }
    } else if (scope_type == search_scope_type::mrt_stack) {
        for (size_t t = 0, sz = ctx.t_data.size(); t < sz; t++) {
            const thread_info_dump& tdata = ctx.t_data[t];
            if (((ULONG64)tdata.stack_base >= info.BaseAddress) && (tdata.context->Rsp <= (info.BaseAddress + info.RegionSize))) {
                return true;
            }
        }
    } else if (scope_type == search_scope_type::mrt_other) {
        for (size_t t = 0, sz = ctx.t_data.size(); t < sz; t++) {
            const thread_info_dump& tdata = ctx.t_data[t];
            if (((ULONG64)tdata.stack_base >= info.BaseAddress) && (tdata.context->Rsp <= (info.BaseAddress + info.RegionSize))) {
                return false;
            }
        }
        for (size_t m = 0, sz = ctx.m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx.m_data[m];
            if (((ULONG64)mdata.base_of_image <= info.BaseAddress) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (info.BaseAddress + info.RegionSize))) {
                return false;
            }
        }
        return true;
    }
    return false;
}

static void search_and_sync(search_context_dump& search_ctx) {
    dump_processing_context& ctx = *search_ctx.ctx;

    const uint64_t alloc_granularity = get_alloc_granularity();

    auto& mem_info = search_ctx.mem_info;
    const char* pattern = ctx.common.pdata.pattern;
    const int64_t pattern_len = ctx.common.pdata.pattern_len;
    const bool ranged_search = ctx.common.pdata.scope_type == search_scope_type::mrt_range;

    // collect memory regions
    size_t num_regions = search_ctx.memory_list->NumberOfMemoryRanges;
    mem_info.reserve(num_regions);
    std::vector<uint64_t> rva_offsets; rva_offsets.reserve(num_regions);
    size_t cumulative_offset = 0;
    const bool scoped_search = ctx.common.pdata.scope_type != search_scope_type::mrt_all;
    for (ULONG i = 0; i < num_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = search_ctx.memory_descriptors[i];
        const uint64_t offset = search_ctx.memory_list->BaseRva + cumulative_offset;
        cumulative_offset += mem_desc.DataSize;
        const SIZE_T region_size = static_cast<SIZE_T>(mem_desc.DataSize);
        if ((int64_t)region_size < pattern_len) {
            continue;
        }
        if (scoped_search) {
            if (ranged_search) {
                if (!ranges_intersect((uint64_t)mem_desc.StartOfMemoryRange, mem_desc.DataSize, (uint64_t)ctx.common.pdata.range.start, ctx.common.pdata.range.length)) {
                    continue;
                }
            } else if (!identify_memory_region_type(ctx.common.pdata.scope_type, mem_desc, ctx)) {
                continue;
            }
        }
        mem_info.push_back(mem_desc);
        rva_offsets.push_back(offset);
    }

    num_regions = mem_info.size();
    if (!num_regions) {
        if (remap_file(ctx.file_mapping, &ctx.file_base)) {
            gather_modules(&ctx);
            gather_threads(&ctx);
        }
        return;
    }

    const size_t extra_chunk = multiple_of_n(pattern_len, sizeof(__m128i));
    const size_t block_size = alloc_granularity * g_num_alloc_blocks;
    const size_t bytes_to_read_ideal = block_size + extra_chunk;

    const int num_threads = _min((int)std::thread::hardware_concurrency(), g_max_threads);
    search_ctx.common.workers_sem.set_max_count(num_threads);
    std::vector<char*> buffers(num_threads);
    std::vector<std::thread> workers; workers.reserve(num_threads);
    for (int i = 0; i < num_threads; i++) {
        workers.push_back(std::thread(find_pattern, &search_ctx));
    }

    //produce block_info
    auto& block_info_queue = search_ctx.block_info_queue;
    for (ULONG i = 0; i < num_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = mem_info[i];
        const SIZE_T region_size = static_cast<SIZE_T>(mem_desc.DataSize);

        const uint64_t offset = rva_offsets[i];
        uint64_t offset_aligned = offset & ~(alloc_granularity - 1);
        uint64_t reminder = offset - offset_aligned;
        size_t total_bytes_to_map = region_size + reminder;
        size_t start_offset = 0;

        while (total_bytes_to_map) {
            while (block_info_queue.is_full()) {
                search_ctx.common.master_sem.wait();
            }
            size_t bytes_to_map;
            if (total_bytes_to_map >= bytes_to_read_ideal) {
                bytes_to_map = bytes_to_read_ideal;
                total_bytes_to_map -= block_size;
            } else {
                bytes_to_map = total_bytes_to_map;
                total_bytes_to_map = 0;
            }
            const size_t bytes_to_read = bytes_to_map - reminder;

            const DWORD high = (DWORD)((offset_aligned >> 0x20) & 0xFFFFFFFF);
            const DWORD low = (DWORD)(offset_aligned & 0xFFFFFFFF);
            offset_aligned += block_size;
            if (!ranged_search || ranges_intersect(mem_desc.StartOfMemoryRange + start_offset, bytes_to_read, (uint64_t)ctx.common.pdata.range.start, ctx.common.pdata.range.length)) {
                block_info_dump b = { start_offset, bytes_to_map, bytes_to_read, low, high, i };
                block_info_queue.try_push(b);
                search_ctx.common.workers_sem.signal();
            }
            start_offset += bytes_to_read - extra_chunk;
            reminder = 0;
        }
    }

    search_ctx.common.exit_workers = 1;
    search_ctx.common.workers_sem.signal(num_threads);
    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }

    if (!remap_file(ctx.file_mapping, &ctx.file_base)) {
        return;
    }
    gather_modules(&ctx);
    gather_threads(&ctx);
}

static void print_search_results(search_context_dump& search_ctx) {
    const uint64_t num_matches = prepare_matches(&search_ctx.ctx->common, search_ctx.common.matches);
    if (!num_matches) {
        return;
    }

    printf("*** Total number of matches: %llu ***\n", num_matches);

    uint64_t prev_info_id = (uint64_t)(-1);

    for (size_t i = 0; i < num_matches; i++) {
        const uint32_t info_id = search_ctx.common.matches[i].info_id;
        if (info_id != prev_info_id) {
            puts("\n------------------------------------\n");
            const MINIDUMP_MEMORY_DESCRIPTOR64& r_info = search_ctx.mem_info[info_id];
            bool found_on_stack = false;
            for (size_t t = 0, sz = search_ctx.ctx->t_data.size(); t < sz; t++) {
                const thread_info_dump& tdata = search_ctx.ctx->t_data[t];
                if (((ULONG64)tdata.stack_base >= r_info.StartOfMemoryRange) && (tdata.context->Rsp <= (r_info.StartOfMemoryRange + r_info.DataSize))) {
                    wprintf((LPWSTR)L"Stack: Thread Id 0x%04x\n", tdata.tid);
                    found_on_stack = true;
                    break;
                }
            }
            if (!found_on_stack) {
                for (size_t m = 0, sz = search_ctx.ctx->m_data.size(); m < sz; m++) {
                    const module_data& mdata = search_ctx.ctx->m_data[m];
                    if (((ULONG64)mdata.base_of_image <= r_info.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (r_info.StartOfMemoryRange + r_info.DataSize))) {
                        wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                        break;
                    }
                }
            }
            printf("Start of Memory Region: 0x%p | Region Size: 0x%016llx\n\n",
                (void*)r_info.StartOfMemoryRange, r_info.DataSize);

            prev_info_id = info_id;
        }
        print_match(&search_ctx.common.matches[i], search_ctx.common.mem_snapshots);
    }
    puts("");
}

static void search_pattern_in_memory(dump_processing_context *ctx) {
    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        fprintf(stderr, "Failed to read Memory64ListStream.\n");
        return;
    }

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY64_LIST));
    
    if (ctx->common.rdata.redirect) {
        puts(ctx->common.command);
        puts("");
    }

    puts("\n------------------------------------\n");

    search_context_dump search_ctx;
    search_ctx.memory_list = memory_list;
    search_ctx.memory_descriptors = memory_descriptors;
    search_ctx.ctx = ctx;
    search_ctx.common.exit_workers = 0;

    search_and_sync(search_ctx);
    print_search_results(search_ctx);

}

static void search_pattern_in_registers(const dump_processing_context *ctx) {
    std::vector<reg_search_result> matches;
    reg_search_result match;
    match.reg_name[0] = 'R';
    match.reg_name[3] = 0;
    const uint8_t* pattern = (const uint8_t*)ctx->common.pdata.pattern;
    int64_t pattern_len = ctx->common.pdata.pattern_len;
    assert(pattern_len <= sizeof(uint64_t));
    for (const thread_info_dump &data : ctx->t_data) {
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

    if (ctx->common.rdata.redirect) {
        puts(ctx->common.command);
        puts("");
    }
    const size_t num_matches = matches.size();
    if (!num_matches) {
        puts("*** No matches found. ***");
        return;
    }
    if (too_many_results(num_matches, output_redirected(&ctx->common))) {
        return;
    }
    printf("*** Total number of matches: %llu ***\n", num_matches);

    DWORD tid_prev = INVALID_ID;
    for (const reg_search_result &res : matches) {
        if (tid_prev != res.tid) {
            puts("\n------------------------------------\n");
            printf("ThreadID: 0x%04x\n\n", res.tid);
            tid_prev = res.tid;
        }
        printf("\t%s: 0x%016llx\n", res.reg_name, res.match);
    }
    puts("");
}

static void print_hexdump_dump(dump_processing_context* ctx) {
    std::vector<uint8_t> bytes;
    const uint8_t* address = ctx->common.hdata.address;

    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        fprintf(stderr, "Failed to read Memory64ListStream.\n");
        return;
    }
    puts("\n------------------------------------\n");

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY64_LIST));
    const uint64_t alloc_granularity = get_alloc_granularity();
    const size_t num_regions = memory_list->NumberOfMemoryRanges;
    size_t cumulative_offset = 0;

    for (ULONG i = 0; i < num_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = memory_descriptors[i];
        const SIZE_T region_size = static_cast<SIZE_T>(mem_desc.DataSize);
        if (((ULONG64)address >= mem_desc.StartOfMemoryRange) && ((ULONG64)address < (mem_desc.StartOfMemoryRange + region_size))) {
            size_t bytes_to_read = ctx->common.hdata.num_to_display * ctx->common.hdata.mode;
            const ULONG64 start_offset = (ULONG64)address - mem_desc.StartOfMemoryRange;
            bytes_to_read = _min(bytes_to_read, (region_size - start_offset));
            ctx->common.hdata.num_to_display = bytes_to_read / ctx->common.hdata.mode;
            bytes_to_read = ctx->common.hdata.num_to_display * ctx->common.hdata.mode;

            const uint64_t rva_offset = memory_list->BaseRva + cumulative_offset + start_offset;           
            uint64_t rva_offset_aligned = rva_offset & ~(alloc_granularity - 1);
            uint64_t reminder = rva_offset - rva_offset_aligned;
            const size_t bytes_to_map = bytes_to_read + reminder;
            const DWORD high = (DWORD)((rva_offset_aligned >> 0x20) & 0xFFFFFFFF);
            const DWORD low = (DWORD)(rva_offset_aligned & 0xFFFFFFFF);
            HANDLE file_base = MapViewOfFile(ctx->file_mapping, FILE_MAP_READ, high, low, bytes_to_map);
            const char* buffer = ((const char*)file_base + reminder);
            if (!buffer) {
                UnmapViewOfFile(file_base);
                fprintf(stderr, "Empty memory region!\n");
                return;
            }
            bytes.reserve(bytes_to_read);
            for (int i = 0; i < bytes_to_read; i++) {
                bytes.push_back(buffer[i]);
            }

            UnmapViewOfFile(file_base);
            break;
        }
        cumulative_offset += mem_desc.DataSize;
    }

    if (0 == bytes.size()) {
        puts("Address not found in commited memory ranges.");
        return;
    }

    switch (ctx->common.hdata.hex_op.op) {
    case hexdump_op::ho_xor:
        for (int i = 0, j = 0, sz = (int)bytes.size(); i < sz; i++, j = (j + 1) % ctx->common.hdata.hex_op.str_len) {
            bytes[i] ^= ctx->common.hdata.hex_op.hex_str[j];
        }
        break;
    case hexdump_op::ho_and:
        for (int i = 0, j = 0, sz = (int)bytes.size(); i < sz; i++, j = (j + 1) % ctx->common.hdata.hex_op.str_len) {
            bytes[i] &= ctx->common.hdata.hex_op.hex_str[j];
        }
        break;
    default:
        break;
    }

    print_hexdump(ctx->common.hdata, bytes.data(), bytes.size());
}

static void print_help_main() {
    print_help_main_common();
    puts("------------------------------------\n");
}

static void print_help_search() {
    print_help_search_common();
    puts("--------------------------------");
    puts("/xr <pattern>\t\t - search for a hex value in GP registers");
    puts("------------------------------------\n");
}

static void print_help_redirect() {
    print_help_redirect_common();
    puts("------------------------------------\n");
}

static void print_help_hexdump() {
    print_help_hexdump_common();
    puts("------------------------------------\n");
}

static void print_help_list() {
    print_help_list_common();
    puts("------------------------------------");
    puts("lh\t\t\t - list handles");
    puts("ltr\t\t\t - list thread GP registers");
    puts("lmd\t\t\t - list memory regions present in dump");
    puts("------------------------------------\n");
}

static void print_help_inspect() {
    print_help_inspect_common();
    puts("------------------------------------\n");
}

static void print_help_calculate() {
    print_help_calculate_common();
    puts("------------------------------------\n");
}

static void print_help_symbols() {
    if (g_disable_symbols) {
        return;
    }
    print_help_symbols_common();
    puts("------------------------------------\n");
}

static input_command parse_command(dump_processing_context *ctx, search_data_info *data, char *pattern) {
    //char* cmd = ctx->common.command;
    input_command command;
    
    fprintf(stderr, unknown_command);
    command = c_continue;

    return command;
}

static void execute_command(input_command cmd, dump_processing_context *ctx) {
    switch (cmd) {
    case c_help_main :
        print_help_main();
        break;
    case c_help_search:
        print_help_search();
        break;
    case c_help_redirect:
        print_help_redirect();
        break;
    case c_help_list:
        print_help_list();
        break;
    case c_help_hexdump:
        print_help_hexdump();
        break;
    case c_help_inspect:
        print_help_inspect();
        break;
    case c_help_calculate:
        print_help_calculate();
        break;
    case c_help_symbols:
        print_help_symbols();
        break;
    case c_search_pattern :
        wait_for_memory_regions_caching(&ctx->pages_caching_state);
        try_redirect_output_to_file(&ctx->common);
        search_pattern_in_memory((dump_processing_context*)ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_search_pattern_in_registers :
        try_redirect_output_to_file(&ctx->common);
        search_pattern_in_registers(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_print_hexdump:
        try_redirect_output_to_file(&ctx->common);
        print_hexdump_dump(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_modules:
        try_redirect_output_to_file(&ctx->common);
        list_modules(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_threads:
        try_redirect_output_to_file(&ctx->common);
        list_threads(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_thread_registers:
        try_redirect_output_to_file(&ctx->common);
        list_thread_registers(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_dump_memory_regions :
        try_redirect_output_to_file(&ctx->common);
        if (!list_memory64_regions(ctx)) {
            list_memory_regions(ctx);
        }
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_memory_regions_info :
        try_redirect_output_to_file(&ctx->common);
        list_memory_regions_info(ctx, false);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_memory_regions_info_committed:
        try_redirect_output_to_file(&ctx->common);
        list_memory_regions_info(ctx, true);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_handles:
        try_redirect_output_to_file(&ctx->common);
        list_handle_descriptors(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_inspect_memory:
        try_redirect_output_to_file(&ctx->common);
        print_memory_info(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_inspect_module:
        try_redirect_output_to_file(&ctx->common);
        print_module_info(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_inspect_thread:
        try_redirect_output_to_file(&ctx->common);
        print_thread_info(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_inspect_image:
        try_redirect_output_to_file(&ctx->common);
        print_image_info(&ctx->common);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_calculate:
        try_redirect_output_to_file(&ctx->common);
        data_block_calculate(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_symbol_resolve_at_address:
        try_redirect_output_to_file(&ctx->common);
        symbol_find_at_address(&ctx->common);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_symbol_resolve_by_name:
        try_redirect_output_to_file(&ctx->common);
        symbol_find_by_name(&ctx->common);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_symbol_resolve_fwd:
        try_redirect_output_to_file(&ctx->common);
        symbol_find_next(&ctx->common);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_symbol_resolve_bwd:
        try_redirect_output_to_file(&ctx->common);
        symbol_find_prev(&ctx->common);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_symbol_get_path:
        symbol_get_path(&ctx->common);
        puts("====================================\n");
        break;
    case c_symbol_set_path:
        symbol_set_path(ctx);
        puts("====================================\n");
        break;
    default :
        fprintf(stderr, unknown_command);
        break;
    }
}

int run_dump_inspection() {
    char dump_file_path[MAX_PATH];
    memset(dump_file_path, 0, sizeof(dump_file_path));
    printf("\nProvide the absolute path to the dmp file: ");
    gets_s(dump_file_path, sizeof(dump_file_path));

    HANDLE file_handle, file_mapping_handle, file_base;
    if (!map_file(dump_file_path, &file_handle, &file_mapping_handle, &file_base)) {
        return -1;
    }

    dump_processing_context ctx = { { pattern_data{ nullptr, 0, search_scope_type::mrt_all } }, file_handle, file_mapping_handle, file_base };
    get_system_info(&ctx);
    if (ctx.cpu_info.processor_architecture != PROCESSOR_ARCHITECTURE_AMD64) {
        fprintf(stderr, "\nOnly x86-64 architecture supported at the moment. Exiting..\n");
        return -1;
    }

    if (!is_drive_ssd(dump_file_path)) {
        puts("\nFile is located on an HDD which is going to negatively affect performance.");
    }

#ifndef DISABLE_STANDBY_LIST_PURGE
    if (g_purge_standby_pages) {
        if (is_elevated()) {
            purge_standby_list();
        } else {
            fprintf(stderr, "\n***Standby pages purging requires elevated priveleges.\n");
        }
    }
#endif // DISABLE_STANDBY_LIST_PURGE

    // pre-cache physical pages
    std::thread page_caching_thread;
    if (!g_disable_page_caching) {
        LARGE_INTEGER file_size; file_size.QuadPart = 0;
        GetFileSizeEx(file_handle, &file_size);
        if (0 != file_size.QuadPart) {
            DWORDLONG available_phys_mem, total_phys_mem;
            if (get_available_phys_memory(&total_phys_mem, &available_phys_mem)) {
                const int64_t delta = (int64_t)available_phys_mem - (int64_t)file_size.QuadPart;
                const int64_t threshold = -(int64_t)total_phys_mem / AVAIL_PHYS_MEM_FACTOR;
                if ((delta > 0) || (delta > threshold)) {
                    if (g_max_threads == INVALID_THREAD_NUM) { // no -t || --threads cmd arg has been passed
                        g_max_threads = IDEAL_THREAD_NUM_DUMP_W_CACHING;
                    }
                    ctx.pages_caching_state.ready = 0;
                    page_caching_thread = std::thread(cache_memory_regions, &ctx);
                }
            }
        }
    }
    // file is not being cached - use fewer threads
    if (g_max_threads == INVALID_THREAD_NUM) { // no -t || --threads cmd arg has been passed
        g_max_threads = IDEAL_THREAD_NUM_DUMP;
    }

    puts("");
    print_help_main();

    gather_modules(&ctx);
    gather_threads(&ctx);

    if (!g_disable_symbols) {
        init_symbols(&ctx);
    }

    char pattern[MAX_PATTERN_LEN];
    char command[MAX_COMMAND_LEN + MAX_ARG_LEN];
    ctx.common.command = command;
    search_data_info sdata;

    while (1) {
        printf(">: ");
        input_command cmd = parse_command_common(&ctx.common, &sdata, pattern);
        if (cmd == input_command::c_not_set) {
            cmd = parse_command(&ctx, &sdata, pattern);
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

    stop_memory_regions_caching(&ctx.pages_caching_state, page_caching_thread);

    // epilogue
    if (!g_disable_symbols) {
        deinit_symbols(&ctx.common);
    }
    UnmapViewOfFile(file_base);
    CloseHandle(file_mapping_handle);
    CloseHandle(file_handle);

    return 0;
}

static void get_system_info(dump_processing_context* ctx) {
    MINIDUMP_SYSTEM_INFO* system_info = nullptr;
    ULONG stream_size = 0;
    ctx->cpu_info.processor_architecture = PROCESSOR_ARCHITECTURE_UNKNOWN;
    if (!MiniDumpReadDumpStream(ctx->file_base, SystemInfoStream, nullptr, reinterpret_cast<void**>(&system_info), &stream_size)) {
        fprintf(stderr, "Failed to read SystemInfoStream.\n");
    }
    ctx->cpu_info.processor_architecture = system_info->ProcessorArchitecture;
}

static void gather_modules(dump_processing_context *ctx) {
    // Retrieve the Memory64ListStream
    MINIDUMP_MODULE_LIST* module_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, ModuleListStream, nullptr, reinterpret_cast<void**>(&module_list), &stream_size)) {
        fprintf(stderr, "Failed to read ModuleListStream.\n");
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

static void gather_threads(dump_processing_context *ctx) {
    MINIDUMP_THREAD_LIST* thread_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, ThreadListStream, nullptr, reinterpret_cast<void**>(&thread_list), &stream_size)) {
        fprintf(stderr, "Failed to read ThreadListStream.\n");
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

static bool list_memory64_regions(const dump_processing_context* ctx) {

    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        fprintf(stderr, "Failed to read Memory64ListStream.\n");
        return false;
    }

    // Parse and list memory regions
    const ULONG64 num_memory_regions =  memory_list->NumberOfMemoryRanges;
    if (too_many_results(num_memory_regions, output_redirected(&ctx->common))) {
        return true;
    }

    printf("*** Number of Memory Regions: %llu ***\n\n", num_memory_regions);

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list) + sizeof(MINIDUMP_MEMORY64_LIST));

    ULONG prev_module = (ULONG)(-1);
    for (ULONG i = 0; i < num_memory_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = memory_descriptors[i];
        for (ULONG m = 0, sz = (ULONG)ctx->m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx->m_data[m];
            if ((prev_module != m) && ((ULONG64)mdata.base_of_image <= mem_desc.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_desc.StartOfMemoryRange + mem_desc.DataSize))) {
                puts("------------------------------------\n");
                wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                prev_module = m;
                break;
            }
        }
        printf("Start Address: 0x%p | Size: 0x%016llx\n", (void*)mem_desc.StartOfMemoryRange, mem_desc.DataSize);
    }
    puts("");

    return true;
}

static bool list_memory_regions(const dump_processing_context* ctx) {

    MINIDUMP_MEMORY_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, MemoryListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        fprintf(stderr, "Failed to read MemoryListStream.\n");
        return false;
    }

    // Parse and list memory regions
    const ULONG64 num_memory_regions = memory_list->NumberOfMemoryRanges;
    if (too_many_results(num_memory_regions, output_redirected(&ctx->common))) {
        return true;
    }

    printf("*** Number of Memory Regions: %llu ***\n\n", num_memory_regions);

    const MINIDUMP_MEMORY_DESCRIPTOR* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY_LIST));
    
    ULONG prev_module = (ULONG)(-1);
    for (ULONG i = 0; i < num_memory_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR& mem_desc = memory_descriptors[i];
        for (ULONG m = 0, sz = (ULONG)ctx->m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx->m_data[m];
            if ((prev_module != m) && ((ULONG64)mdata.base_of_image <= mem_desc.StartOfMemoryRange) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_desc.StartOfMemoryRange + mem_desc.Memory.DataSize))) {
                puts("------------------------------------\n");
                wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                prev_module = m;
                break;
            }
        }
        printf("Start Address: 0x%p\n", (void*)mem_desc.StartOfMemoryRange);
    }
    puts("");

    return true;
}

static void list_modules(const dump_processing_context* ctx) {
    const ULONG64 num_modules = ctx->m_data.size();
    if (too_many_results(num_modules, output_redirected(&ctx->common))) {
        return;
    }

    printf("*** Number of Modules: %llu ***\n\n", num_modules);

    for (ULONG i = 0; i < num_modules; i++) {
        const module_data& module = ctx->m_data[i];
        wprintf((LPWSTR)L"Module name: %s\n", module.name);
        printf("Base of image: 0x%p | Size of image: 0x%04llx\n\n", module.base_of_image, module.size_of_image);
    }
}

static void list_threads(const dump_processing_context* ctx) {
    const ULONG64 num_threads = ctx->t_data.size();

    if (too_many_results(num_threads, output_redirected(&ctx->common))) {
        return;
    }

    printf("*** Number of threads: %llu ***\n\n", num_threads);

    for (ULONG i = 0; i < num_threads; i++) {
        const thread_info_dump& thread = ctx->t_data[i];
        printf("ThreadID: 0x%04x | Priority Class: 0x%04x | Priority: 0x%04x | Stack Base: 0x%p | RSP: 0x%p\n\n",
            thread.tid, thread.priority_class, thread.priority, (char*)thread.stack_base, (char*)thread.context->Rsp);
    }
}

static void list_thread_registers(const dump_processing_context* ctx) {
    const ULONG64 num_threads = ctx->t_data.size();

    if (too_many_results(num_threads, output_redirected(&ctx->common))) {
        return;
    }

    printf("*** Number of threads: %llu ***\n\n", num_threads);

    for (ULONG i = 0; i < num_threads; i++) {
        const thread_info_dump& thread = ctx->t_data[i];
        printf("*** ThreadID: 0x%04x ***\nRAX: 0x%p RBX: 0x%p RCX: 0x%p RDX: 0x%p\n", thread.tid,
            (char*)thread.context->Rax, (char*)thread.context->Rbx, (char*)thread.context->Rcx, (char*)thread.context->Rdx);
        printf("RDI: 0x%p RSI: 0x%p RSP: 0x%p RBP: 0x%p\n",
            (char*)thread.context->Rdi, (char*)thread.context->Rsi, (char*)thread.context->Rsp, (char*)thread.context->Rbp);
        printf("R8:  0x%p R9:  0x%p R10: 0x%p R11: 0x%p\n",
            (char*)thread.context->R8, (char*)thread.context->R9, (char*)thread.context->R10, (char*)thread.context->R11);
        printf("R12: 0x%p R13: 0x%p R14: 0x%p R15: 0x%p\n",
            (char*)thread.context->R11, (char*)thread.context->R12, (char*)thread.context->R13, (char*)thread.context->R14);
        printf("RIP: 0x%p\tRFLAGS: 0x%08x\tMXCSR: 0x%08x\n",
            (char*)thread.context->Rip, thread.context->EFlags, thread.context->MxCsr);
        puts("\n----------------\n");
    }
}

static void list_memory_regions_info(const dump_processing_context* ctx, bool show_commited) {
    MINIDUMP_MEMORY_INFO_LIST* memory_info_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, MemoryInfoListStream, nullptr, reinterpret_cast<void**>(&memory_info_list), &stream_size)) {
        fprintf(stderr, "Failed to read MemoryInfoListStream.\n");
        return;
    }

    const bool scoped_search = ctx->common.pdata.scope_type != search_scope_type::mrt_all;

    const ULONG64 num_entries = memory_info_list->NumberOfEntries;
    if (!scoped_search && too_many_results(num_entries, output_redirected(&ctx->common))) {
        return;
    }

    const MINIDUMP_MEMORY_INFO* memory_info = (MINIDUMP_MEMORY_INFO*)((char*)(memory_info_list) + sizeof(MINIDUMP_MEMORY_INFO_LIST));

    ULONG prev_module = (ULONG)(-1);
    uint64_t num_regions = 0;
    for (ULONG i = 0; i < memory_info_list->NumberOfEntries; ++i) {
        const MINIDUMP_MEMORY_INFO& mem_info = memory_info[i];
        if (show_commited && (mem_info.State != MEM_COMMIT)) {
            continue;
        }

        if (scoped_search && !identify_memory_region_type(ctx->common.pdata.scope_type, mem_info, *ctx)) {
            continue;
        }

        num_regions++;
        for (ULONG m = 0, sz = (ULONG)ctx->m_data.size(); m < sz; m++) {
            const module_data& mdata = ctx->m_data[m];
            if ((prev_module != m) && ((ULONG64)mdata.base_of_image <= mem_info.BaseAddress) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_info.BaseAddress + mem_info.RegionSize))) {
                puts("------------------------------------\n");
                wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                prev_module = m;
                break;
            }
        }
        printf("Base Address: 0x%p | Size: 0x%016llx | State: %s\t | Protect: %s\t",
            (void*)memory_info[i].BaseAddress, memory_info[i].RegionSize, 
            get_page_state(mem_info.State), get_page_protect(mem_info.Protect));
        print_page_type(mem_info.Type);
    }
    puts("");
    printf("*** Number of Memory Info Entries: %llu ***\n\n", num_regions);
}

static void print_memory_info(const dump_processing_context* ctx) {
    MINIDUMP_MEMORY_INFO_LIST* memory_info_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, MemoryInfoListStream, nullptr, reinterpret_cast<void**>(&memory_info_list), &stream_size)) {
        fprintf(stderr, "Failed to read MemoryInfoListStream.\n");
        return;
    }
    const MINIDUMP_MEMORY_INFO* memory_info = (MINIDUMP_MEMORY_INFO*)((char*)(memory_info_list)+sizeof(MINIDUMP_MEMORY_INFO_LIST));

    for (ULONG i = 0; i < memory_info_list->NumberOfEntries; ++i) {
        const MINIDUMP_MEMORY_INFO& mem_info = memory_info[i];

        if (((ULONG64)ctx->common.i_data.memory_address < mem_info.BaseAddress) || ((ULONG64)ctx->common.i_data.memory_address >= (mem_info.BaseAddress + mem_info.RegionSize))) {
            continue;
        }

        bool found_on_stack = false;
        if (mem_info.Type == MEM_PRIVATE) {
            for (size_t t = 0, sz = ctx->t_data.size(); t < sz; t++) {
                const thread_info_dump& tdata = ctx->t_data[t];
                if (((ULONG64)tdata.stack_base >= mem_info.BaseAddress) && (tdata.context->Rsp <= (mem_info.BaseAddress + mem_info.RegionSize))) {
                    wprintf((LPWSTR)L"Stack: Thread Id 0x%04x\n", tdata.tid);
                    found_on_stack = true;
                    break;
                }
            }
        }
        if (!found_on_stack && (mem_info.Type == MEM_IMAGE)) {
            for (size_t m = 0, sz = ctx->m_data.size(); m < sz; m++) {
                const module_data& mdata = ctx->m_data[m];
                if (((ULONG64)mdata.base_of_image <= mem_info.BaseAddress) && (((ULONG64)mdata.base_of_image + mdata.size_of_image) >= (mem_info.BaseAddress + mem_info.RegionSize))) {
                    wprintf((LPWSTR)L"Module name: %s\n", mdata.name);
                    break;
                }
            }
        }
        printf("Base Address: 0x%p | Size: 0x%016llx | State: %s\t | Protect: %s\t",
            (void*)memory_info[i].BaseAddress, memory_info[i].RegionSize,
            get_page_state(mem_info.State), get_page_protect(mem_info.Protect));
        print_page_type(mem_info.Type);
        puts("");
        break;
    }
}

static void print_module_info(const dump_processing_context* ctx) {

#ifdef _UNICODE
    LPCWSTR module_name = ctx->common.i_data.module_name;
#elif defined(_MBCS )
    WCHAR module_name[MAX_PATH];
    memset(module_name, 0, sizeof(module_name));
    const int wc_size = MultiByteToWideChar(CP_UTF8, 0, ctx->common.i_data.module_name, -1, NULL, 0);
    if (wc_size && (wc_size <= _countof(ctx->common.i_data.module_name))) {
        int result = MultiByteToWideChar(CP_UTF8, 0, ctx->common.i_data.module_name, -1, module_name, wc_size);
        if (result == 0) {
            fwprintf(stderr, L"Error converting to wide character string: %s\n", module_name);
            return;
        }
    } else {
        fwprintf(stderr, L"Module name exceeds maximum length: %s\n", module_name);
        return;
    }
#endif

    for (ULONG i = 0, num_modules = (ULONG)ctx->m_data.size(); i < num_modules; i++) {
        const module_data& m = ctx->m_data[i];
        if (nullptr == wcsstr(m.name, module_name)) {
            continue;
        }
        wprintf((LPCWSTR)L"Module name: %s\n", m.name);
        printf("Base of image: 0x%p | Size of image: 0x%04llx\n\n", m.base_of_image, m.size_of_image);
        break;
    }
}

static void print_thread_info(const dump_processing_context* ctx) {
    bool found = false;
    for (ULONG i = 0, num_threads = (ULONG)ctx->t_data.size(); i < num_threads; i++) {
        const thread_info_dump& thread = ctx->t_data[i];
        if (thread.tid != ctx->common.i_data.tid) {
            continue;
        }
        printf("ThreadID: 0x%04x | Priority Class: 0x%04x | Priority: 0x%04x | Stack Base: 0x%p\n\n",
            thread.tid, thread.priority_class, thread.priority, (char*)thread.stack_base);
        printf("RAX: 0x%p RBX: 0x%p RCX: 0x%p RDX: 0x%p\n",
            (char*)thread.context->Rax, (char*)thread.context->Rbx, (char*)thread.context->Rcx, (char*)thread.context->Rdx);
        printf("RDI: 0x%p RSI: 0x%p RSP: 0x%p RBP: 0x%p\n",
            (char*)thread.context->Rdi, (char*)thread.context->Rsi, (char*)thread.context->Rsp, (char*)thread.context->Rbp);
        printf("R8:  0x%p R9:  0x%p R10: 0x%p R11: 0x%p\n",
            (char*)thread.context->R8, (char*)thread.context->R9, (char*)thread.context->R10, (char*)thread.context->R11);
        printf("R12: 0x%p R13: 0x%p R14: 0x%p R15: 0x%p\n",
            (char*)thread.context->R11, (char*)thread.context->R12, (char*)thread.context->R13, (char*)thread.context->R14);
        printf("RIP: 0x%p\tRFLAGS: 0x%08x\tMXCSR: 0x%08x\n",
            (char*)thread.context->Rip, thread.context->EFlags, thread.context->MxCsr);
        puts("");

        found = true;
        break;
    }
    if (!found) {
        printf("Thread 0x%x not found.\n\n", ctx->common.i_data.tid);
    }
}

static void list_handle_descriptors(const dump_processing_context* ctx) {
    MINIDUMP_DIRECTORY* directory;
    MINIDUMP_HANDLE_DATA_STREAM* handle_stream;
    ULONG stream_size;

    if (MiniDumpReadDumpStream(ctx->file_base, HandleDataStream, &directory, (void**)&handle_stream, &stream_size)) {
        printf("Number of handles: %lu\n", handle_stream->NumberOfDescriptors);

        MINIDUMP_HANDLE_DESCRIPTOR_2* handles = (MINIDUMP_HANDLE_DESCRIPTOR_2*)(handle_stream + 1);
        for (ULONG i = 0; i < handle_stream->NumberOfDescriptors; i++) {
            printf("Handle: 0x%llx\n", (unsigned long long)handles[i].Handle);

            // Print type name directly
            MINIDUMP_STRING* type_name_rva = (MINIDUMP_STRING*)((uintptr_t)ctx->file_base + handles[i].TypeNameRva);
            if (type_name_rva && type_name_rva->Buffer) {
                printf("Type: %ls", type_name_rva->Buffer);
                puts("");
            } else {
                printf("Type: (null)\n");
            }

            // Print object name directly
            MINIDUMP_STRING* object_name_rva = (MINIDUMP_STRING*)((uintptr_t)ctx->file_base + handles[i].ObjectNameRva);
            if (object_name_rva && object_name_rva->Buffer) {
                printf("Object Name: %ls", object_name_rva->Buffer);
                puts("");
            } else {
                printf("Object Name: (null)\n");
            }

            printf("Attributes: 0x%lx\n", handles[i].Attributes);
            printf("Granted Access: 0x%lx\n", handles[i].GrantedAccess);
            printf("Handle Count: %lu\n", handles[i].HandleCount);
            printf("Pointer Count: %lu\n", handles[i].PointerCount);
            printf("-----------------------\n");
        }
    } else {
        fprintf(stderr, "Failed to read HandleDataStream.\n");
    }
    puts("");
}

static void data_block_calculate(dump_processing_context* ctx) {
    std::vector<uint8_t> bytes;
    const uint8_t* address = ctx->common.cdata.address;

    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        fprintf(stderr, "Failed to read Memory64ListStream.\n");
        return;
    }
    puts("\n------------------------------------\n");

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY64_LIST));
    const uint64_t alloc_granularity = get_alloc_granularity();
    const size_t num_regions = memory_list->NumberOfMemoryRanges;
    size_t cumulative_offset = 0;

    for (ULONG i = 0; i < num_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = memory_descriptors[i];
        const SIZE_T region_size = static_cast<SIZE_T>(mem_desc.DataSize);
        if (((ULONG64)address >= mem_desc.StartOfMemoryRange) && ((ULONG64)address < (mem_desc.StartOfMemoryRange + region_size))) {
            size_t bytes_to_read = ctx->common.cdata.size;
            const ULONG64 start_offset = (ULONG64)address - mem_desc.StartOfMemoryRange;
            bytes_to_read = _min(bytes_to_read, (region_size - start_offset));

            const uint64_t rva_offset = memory_list->BaseRva + cumulative_offset + start_offset;
            uint64_t rva_offset_aligned = rva_offset & ~(alloc_granularity - 1);
            uint64_t reminder = rva_offset - rva_offset_aligned;
            const size_t bytes_to_map = bytes_to_read + reminder;
            const DWORD high = (DWORD)((rva_offset_aligned >> 0x20) & 0xFFFFFFFF);
            const DWORD low = (DWORD)(rva_offset_aligned & 0xFFFFFFFF);
            HANDLE file_base = MapViewOfFile(ctx->file_mapping, FILE_MAP_READ, high, low, bytes_to_map);
            const char* buffer = ((const char*)file_base + reminder);
            if (!buffer) {
                UnmapViewOfFile(file_base);
                fprintf(stderr, "Empty memory region!\n");
                return;
            }
            bytes.reserve(bytes_to_read);
            for (int i = 0; i < bytes_to_read; i++) {
                bytes.push_back(buffer[i]);
            }

            UnmapViewOfFile(file_base);
            break;
        }
        cumulative_offset += mem_desc.DataSize;
    }

    if (0 == bytes.size()) {
        puts("Address not found in commited memory ranges.");
        return;
    }

    data_block_calculate_common(&ctx->common.cdata, bytes.data(), bytes.size());
}

static bool init_symbols(dump_processing_context* ctx) {
    if (!ctx->common.sym_ctx.ctx_initialized) {
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

        if (!SymInitialize(ctx->file_handle, NULL, FALSE)) {
            fprintf(stderr, "Failed to initialise symbol handler. Error: %lu\n", GetLastError());
            return false;
        }
        
        ctx->common.sym_ctx.process = ctx->file_handle;
        ctx->common.sym_ctx.ctx_initialized = true;
    }
    return true;
}

static void deinit_symbols(common_processing_context* ctx) {
    if (ctx->sym_ctx.ctx_initialized) {
        if (!SymCleanup(ctx->sym_ctx.process)) {
            fprintf(stderr, "Failed to clean up symbol handler. Error: %lu\n", GetLastError());
        }
    }
    ctx->sym_ctx.ctx_initialized = false;
    ctx->sym_ctx.sym_initialized = false;
}

void reload_modules(const dump_processing_context* ctx) {
    const auto& mdata = ctx->m_data;
    printf("Loading symbols for %llu modules...\n", mdata.size());
    char module_path[MAX_PATH];
    for (const auto& m : mdata) {
        if (m.name != nullptr) {
            SymUnloadModule(ctx->file_handle, (DWORD64)m.base_of_image);
            memset(module_path, 0, sizeof(module_path));
            WideCharToMultiByte(CP_ACP, 0, m.name, -1, module_path, sizeof(module_path), NULL, NULL);
            if (module_path == 0) {
                fprintf(stderr, "Failed to extract module name for module at base 0x%p\n", m.base_of_image);
                continue;
            }
            size_t module_len = strlen(module_path);
            while (module_len--) {
                if (module_path[module_len] == '\\' || module_path[module_len] == '/') {
                    module_len++;
                    break;
                }
            }
            const char* module_name = module_path + module_len;
            DWORD64 base_of_dll = (DWORD64)m.base_of_image;
            DWORD64 size_of_dll = m.size_of_image;
            if (SymLoadModuleEx(ctx->file_handle, NULL, module_name, module_name, base_of_dll, (DWORD)size_of_dll, NULL, 0)) {
                printf("Loaded symbols for module: %s (Base: 0x%016llx)\n", module_name, base_of_dll);
            } else {
                fprintf(stderr, "Failed to load symbols for module: %s. Error: %lu\n", module_name, GetLastError());
            }
        }
    }
}

void symbol_set_path(const dump_processing_context* ctx) {
    if (!symbol_set_path_common(&ctx->common)) {
        return;
    }

    reload_modules(ctx);
}

static bool is_drive_ssd(const char* file_path) {
    char volume_path[MAX_PATH] = {0};

    // Get the root path of the volume from the file path
    if (!GetVolumePathNameA(file_path, volume_path, MAX_PATH)) {
        fprintf(stderr, "Failed to get volume path for file: %s\nError: %lu\n", file_path, GetLastError());
        return false;
    }

    // Construct the device path (e.g., \\.\C:)
    char device_path[] = "\\\\.\\A:";
    device_path[4] = volume_path[0]; // Replace 'A' with the drive letter

    HANDLE device_handle = CreateFileA(device_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, 0, NULL);
    if (device_handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to open device: %s\nError: %lu\n", device_path, GetLastError());
        return false;
    }

    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceSeekPenaltyProperty;
    query.QueryType = PropertyStandardQuery;

    DEVICE_SEEK_PENALTY_DESCRIPTOR descriptor = {};
    DWORD bytes_returned = 0;

    BOOL result = DeviceIoControl(device_handle, IOCTL_STORAGE_QUERY_PROPERTY,
                                  &query, sizeof(query),
                                  &descriptor, sizeof(descriptor),
                                  &bytes_returned, NULL);

    CloseHandle(device_handle);

    if (result) {
        return !descriptor.IncursSeekPenalty; // SSDs have no seek penalty
    } else {
        fprintf(stderr, "DeviceIoControl failed with error: %lu\n", GetLastError());
        return false;
    }
}

static DWORD get_page_size() {
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    return system_info.dwPageSize;
}

static void cache_memory_regions(dump_processing_context* ctx) {
    const DWORD page_size = get_page_size();

    MINIDUMP_MEMORY64_LIST* memory_list = nullptr;
    ULONG stream_size = 0;
    if (!MiniDumpReadDumpStream(ctx->file_base, Memory64ListStream, nullptr, reinterpret_cast<void**>(&memory_list), &stream_size)) {
        fprintf(stderr, "Failed to read Memory64ListStream.\n");
        return;
    }

    const MINIDUMP_MEMORY_DESCRIPTOR64* memory_descriptors = (MINIDUMP_MEMORY_DESCRIPTOR64*)((char*)(memory_list)+sizeof(MINIDUMP_MEMORY64_LIST));

    const uint64_t alloc_granularity = get_alloc_granularity();
    size_t num_regions = memory_list->NumberOfMemoryRanges;   
    size_t cumulative_offset = 0;

    const size_t block_size = alloc_granularity * g_num_alloc_blocks;

    for (ULONG i = 0; i < num_regions; ++i) {
        const MINIDUMP_MEMORY_DESCRIPTOR64& mem_desc = memory_descriptors[i];
        const uint64_t offset = memory_list->BaseRva + cumulative_offset;
        cumulative_offset += mem_desc.DataSize;
        const SIZE_T region_size = static_cast<SIZE_T>(mem_desc.DataSize);

        uint64_t offset_aligned = offset & ~(alloc_granularity - 1);
        uint64_t reminder = offset - offset_aligned;
        size_t total_bytes_to_map = region_size + reminder;

        while (total_bytes_to_map) {
            size_t bytes_to_map;
            if (total_bytes_to_map >= block_size) {
                bytes_to_map = block_size;
                total_bytes_to_map -= block_size;
            } else {
                bytes_to_map = total_bytes_to_map;
                total_bytes_to_map = 0;
            }
            const size_t bytes_to_read = bytes_to_map - reminder;

            const DWORD high = (DWORD)((offset_aligned >> 0x20) & 0xFFFFFFFF);
            const DWORD low = (DWORD)(offset_aligned & 0xFFFFFFFF);
            offset_aligned += block_size;

            HANDLE file_base = MapViewOfFile(ctx->file_mapping, FILE_MAP_READ, high, low, bytes_to_map);
            if (!file_base) {
                fprintf(stderr, "Failed to map view of file.\n");
                continue;
            }
            const char* buffer = ((const char*)file_base + reminder);
            volatile char dummy = 0;
            for (int j = 0; j < bytes_to_read; j += page_size) {
                dummy = buffer[j];
            }

            UnmapViewOfFile(file_base);
            reminder = 0;

            if (ctx->pages_caching_state.interrupt) {
                return;
            }
        }
    }

    ctx->pages_caching_state.ready = 1;
}

static void wait_for_memory_regions_caching(cache_memory_regions_ctx* ctx) {
    if (g_disable_page_caching || ctx->ready) {
        return;
    }
    
    printf("Caching memory regions..");
    int line_counter = 0;
    int dot_counter = 0;
    while (!ctx->ready) {
        if (dot_counter++ > NEXT_DOT_INTERVAL) {
            printf(".");
            dot_counter = 0;
            if (line_counter++ > NUM_WAITING_DOTS) {
                puts("");
                line_counter = 0;
            }
        }
        Sleep(WAIT_FOR_MS);
    }
    puts("");
}

static void stop_memory_regions_caching(cache_memory_regions_ctx* ctx, std::thread& t) {
    ctx->interrupt = true;
    if (t.joinable()) {
        t.join();
    }
}

static bool is_elevated() {
    HANDLE token = nullptr;
    TOKEN_ELEVATION elevation;
    DWORD size = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        fprintf(stderr, "Failed to get process token.\n");
        return false;
    }

    if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        CloseHandle(token);
        fprintf(stderr, "Failed to get token information.\n");
        return false;
    }

    CloseHandle(token);

    return elevation.TokenIsElevated;
}

#ifndef DISABLE_STANDBY_LIST_PURGE

void enable_privilege(LPCTSTR privilegeName) {
    HANDLE token;
    TOKEN_PRIVILEGES tp;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        LookupPrivilegeValue(nullptr, privilegeName, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
    }
}

typedef enum _MEMORY_LIST_COMMAND {
    MemoryCaptureAccessedBits = 0,
    MemoryPurgeStandbyList = 4,
    MemoryPurgeLowPriorityStandbyList = 5,
    MemoryCommandMax
} MEMORY_LIST_COMMAND;

static bool purge_standby_list() {
    enable_privilege(SE_LOCK_MEMORY_NAME);
    enable_privilege(SE_PROF_SINGLE_PROCESS_NAME);
    enable_privilege(SE_DEBUG_NAME);
    enable_privilege(SE_INCREASE_QUOTA_NAME);

    HMODULE ntdll = LoadLibrary(TEXT("ntdll.dll"));
    if (!ntdll) {
        fprintf(stderr, "Failed to load ntdll.dll\n");
        return false;
    }

    typedef NTSTATUS(WINAPI* NtSetSystemInformation_t)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength
        );

    auto NtSetSystemInformation = (NtSetSystemInformation_t)GetProcAddress(ntdll, "NtSetSystemInformation");
    if (!NtSetSystemInformation) {
        fprintf(stderr, "Failed to find NtSetSystemInformation\n");
        return false;
    }

    MEMORY_LIST_COMMAND command = MemoryPurgeStandbyList;
    constexpr ULONG SystemMemoryListInformation = 0x50;
    NTSTATUS status = NtSetSystemInformation(SystemMemoryListInformation, &command, sizeof(command));
    if (status != 0) {
        printf("Failed to purge standby list, NTSTATUS: 0x%x\n", status);
        return false;
    }

    return true;
}

#endif // DISABLE_STANDBY_LIST_PURGE