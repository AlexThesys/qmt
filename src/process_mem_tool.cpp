#include "common.h"

#pragma comment(lib, "Onecore.lib")

struct proc_processing_context {
    common_processing_context common;
    DWORD pid;
};

struct block_info_proc {
    const char* ptr;
    size_t size;
    size_t info_id;
};

struct search_context_proc {
    circular_buffer<block_info_proc, SEARCH_DATA_QUEUE_SIZE_POW2> block_info_queue;
    std::vector<MEMORY_BASIC_INFORMATION> mem_info;
    HANDLE process = NULL;
    uint64_t block_size_ideal = 0;
    proc_processing_context *ctx = nullptr;
    search_context_common common{};
    std::mutex err_mtx;
};

struct thread_info_proc {
    DWORD thread_id;
    LONG base_prio;
    LONG delta_prio;
    DWORD_PTR stack_ptr;
    SIZE_T stack_size;
};

static int list_processes();
static int list_process_modules(DWORD dw_pid);
static int list_process_threads(DWORD dw_owner_pid);
static int traverse_heap_list(DWORD dw_pid, bool list_blocks, bool calculate_entropy, bool redirected);
static void print_error(TCHAR const* msg);
static bool gather_thread_info(DWORD dw_owner_pid, std::vector<thread_info_proc>& thread_info);
static void list_memory_regions_info(const proc_processing_context* ctx, bool show_commited);
static bool test_selected_pid(proc_processing_context* ctx);
static void print_memory_info(const proc_processing_context* ctx);
static void print_module_info(const proc_processing_context* ctx);
static void print_thread_info(const proc_processing_context* ctx);

static void find_pattern(search_context_proc* search_ctx) {
    HANDLE process = search_ctx->process;
    const char* pattern = search_ctx->ctx->common.pdata.pattern;
    const int64_t pattern_len = search_ctx->ctx->common.pdata.pattern_len;
    auto& matches = search_ctx->common.matches;
    auto& mem_info = search_ctx->mem_info;
    auto& block_info_queue = search_ctx->block_info_queue;
    auto& exit_workers = search_ctx->common.exit_workers;

    char* buffer = (char*)malloc(search_ctx->block_size_ideal);
    block_info_proc block;

    const bool ranged_search = search_ctx->ctx->common.pdata.scope_type == search_scope_type::mrt_range;
    const char* range_start = search_ctx->ctx->common.pdata.range.start;
    const char* range_end = search_ctx->ctx->common.pdata.range.start + search_ctx->ctx->common.pdata.range.length;

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

        const size_t info_id = block.info_id;
        const MEMORY_BASIC_INFORMATION& r_info = mem_info[info_id];
        const char* ptr = block.ptr;
        const size_t bytes_to_read = block.size;

        assert((r_info.Type == MEM_MAPPED || r_info.Type == MEM_PRIVATE || r_info.Type == MEM_IMAGE));

        SIZE_T bytes_read;
        const BOOL res = ReadProcessMemory(process, ptr, buffer, bytes_to_read, &bytes_read);

        if (!res || (bytes_read != bytes_to_read)) {
            if (!g_show_failed_readings) {
                if (!res) {
                    continue;
                }
            } else {
                std::unique_lock<std::mutex> lk(search_ctx->err_mtx);
                if (r_info.Type == MEM_IMAGE) {
                    char module_name[MAX_PATH];
                    if (GetModuleFileNameExA(process, (HMODULE)r_info.AllocationBase, module_name, MAX_PATH)) {
                        puts("------------------------------------\n");
                        printf("Module name: %s\n", module_name);
                    }
                }
                printf("Base address: 0x%p\tAllocation Base: 0x%p\tRegion Size: 0x%08llx\nState: %s\tProtect: %s\t",
                    r_info.BaseAddress, r_info.AllocationBase, r_info.RegionSize, get_page_protect(r_info.Protect), get_page_state(r_info.State));
                print_page_type(r_info.Type);
                if (!res) {
                    printf("Failed reading process memory. Error code: %lu\n\n", GetLastError());
                    continue;
                } else {
                    printf("Process memory not read in it's entirety! 0x%llx bytes skipped out of 0x%llx\n\n", (bytes_to_read - bytes_read), bytes_to_read);
                }
            }
        }

        if (bytes_read >= pattern_len) {
            const char* buffer_ptr = buffer;
            int64_t buffer_size = (int64_t)bytes_read;

            while (buffer_size >= pattern_len) {
                const char* old_buf_ptr = buffer_ptr;
                buffer_ptr = (const char*)strstr_u8((const uint8_t*)buffer_ptr, buffer_size, (const uint8_t*)pattern, pattern_len);
                if (!buffer_ptr) {
                    break;
                }

                const ptrdiff_t buffer_offset = buffer_ptr - buffer;
                const char* match = ptr + buffer_offset;
                if (!ranged_search || ((match >= range_start) && ((match < range_end)))) {
                    search_ctx->common.matches_lock.lock();
                    matches.push_back(search_match{ block.info_id, match });
                    search_ctx->common.matches_lock.unlock();
                }
                buffer_ptr++;
                buffer_size -= (buffer_ptr - old_buf_ptr);
            }
        }
    }
    free(buffer);
}

static bool identify_memory_region_type(search_scope_type scope_type, const MEMORY_BASIC_INFORMATION &info, const std::vector<thread_info_proc> &thread_info) {
    if (scope_type == search_scope_type::mrt_image) {
        if (info.Type == MEM_IMAGE) {
            return true;
        }
    } else if (scope_type == search_scope_type::mrt_stack) {
        if (info.Type == MEM_IMAGE) {
            return false;
        }
        for (const auto& ti : thread_info) {
            if (((ULONG64)ti.stack_ptr >= (ULONG64)info.BaseAddress) && ((ULONG64)(ti.stack_ptr - ti.stack_size) <= ((ULONG64)info.BaseAddress + info.RegionSize))) {
                return true;
            }
        }
    } else if (scope_type == search_scope_type::mrt_other) {
        if (info.Type == MEM_IMAGE) {
            return false;
        }
        for (const auto& ti : thread_info) {
            if (((ULONG64)ti.stack_ptr >= (ULONG64)info.BaseAddress) && ((ULONG64)(ti.stack_ptr - ti.stack_size) <= ((ULONG64)info.BaseAddress + info.RegionSize))) {
                return false;
            }
        }
        return true;
    }
    return false;
}

static void search_and_sync(search_context_proc& search_ctx) {
    const proc_processing_context& ctx = *search_ctx.ctx;

    const uint64_t alloc_granularity = get_alloc_granularity();

    std::vector<thread_info_proc> thread_info;
    if ((ctx.common.pdata.scope_type == search_scope_type::mrt_stack) || (ctx.common.pdata.scope_type == search_scope_type::mrt_other)) {
        gather_thread_info(search_ctx.ctx->pid, thread_info);
    }

    // collect memory regions
    auto& mem_info = search_ctx.mem_info;
    const HANDLE process = search_ctx.process;
    const size_t pattern_len = ctx.common.pdata.pattern_len;
    const bool ranged_search = ctx.common.pdata.scope_type == search_scope_type::mrt_range;

    std::vector<const char*> blocks;
    {
        const char* p = NULL;
        MEMORY_BASIC_INFORMATION info;
        const bool scoped_search = ctx.common.pdata.scope_type != search_scope_type::mrt_all;
        for (p = NULL; VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize) {
            if (info.State == MEM_COMMIT) {
                size_t region_size = info.RegionSize;
                if (region_size < pattern_len) {
                    continue;
                }
                if (scoped_search) {
                    if (ranged_search) {
                        if (!ranges_intersect((uint64_t)info.BaseAddress, info.RegionSize, (uint64_t)ctx.common.pdata.range.start, ctx.common.pdata.range.length)) {
                            continue;
                        }
                    } else if (!identify_memory_region_type(ctx.common.pdata.scope_type, info, thread_info)) {
                        continue;
                    }
                }
                mem_info.push_back(info);
                blocks.push_back(p);
            }
        }
    }
    const uint64_t num_regions = mem_info.size();
    if (!num_regions) {
        return;
    }

    const size_t extra_chunk = multiple_of_n(pattern_len, sizeof(__m128i));
    const size_t block_size = alloc_granularity * g_num_alloc_blocks;
    const size_t bytes_to_read_ideal = block_size + extra_chunk;
    search_ctx.block_size_ideal = bytes_to_read_ideal;

    const size_t num_threads = _min(std::thread::hardware_concurrency(), g_max_threads);
    search_ctx.common.workers_sem.set_max_count(num_threads);
    std::vector<std::thread> workers; workers.reserve(num_threads);
    for (size_t i = 0; i < num_threads; i++) {
        workers.push_back(std::thread(find_pattern, &search_ctx));
    }
    
    //produce block_info
    auto& block_info_queue = search_ctx.block_info_queue;
    for (size_t i = 0; i < num_regions; i++) {
        uint64_t region_size = mem_info[i].RegionSize;
        const char* p = blocks[i];
        uint64_t bytes_offset = 0;
        while (region_size) {
            while (block_info_queue.is_full()) {
                search_ctx.common.master_sem.wait();
            }
            size_t bytes_to_read;
            if (region_size >= bytes_to_read_ideal) {
                bytes_to_read = bytes_to_read_ideal;
                region_size -= block_size;
            } else {
                bytes_to_read = region_size;
                region_size = 0;
            }
            const char* block_start = p + bytes_offset;
            if (!ranged_search || ranges_intersect((uint64_t)block_start, bytes_to_read, (uint64_t)ctx.common.pdata.range.start, ctx.common.pdata.range.length)) {
                block_info_proc b = { block_start, bytes_to_read, i };
                block_info_queue.try_push(b);
                search_ctx.common.workers_sem.signal();
            }
            bytes_offset += block_size;
        }
    }

    search_ctx.common.exit_workers = 1;
    search_ctx.common.workers_sem.signal(num_threads);
    for (auto& w : workers) {
        if (w.joinable()) {
            w.join();
        }
    }
}

static void print_search_results(search_context_proc& search_ctx) {
    const uint64_t num_matches = prepare_matches(&search_ctx.ctx->common, search_ctx.common.matches);
    if (!num_matches) {
        return;
    }

    printf("*** Total number of matches: %llu ***\n", num_matches);
    uint64_t prev_info_id = (uint64_t)(-1);

    std::vector<thread_info_proc> thread_info;
    gather_thread_info(search_ctx.ctx->pid, thread_info);

    for (size_t i = 0; i < num_matches; i++) {
        const size_t info_id = search_ctx.common.matches[i].info_id;
        if (info_id != prev_info_id) {
            puts("\n------------------------------------\n");
            const MEMORY_BASIC_INFORMATION& r_info = search_ctx.mem_info[info_id];
            if (r_info.Type == MEM_IMAGE) {
                char module_name[MAX_PATH];
                if (GetModuleFileNameExA(search_ctx.process, (HMODULE)r_info.AllocationBase, module_name, MAX_PATH)) {
                    printf("Module name: %s\n", module_name);
                }
            } else {
                for (const auto& ti : thread_info) {
                    if (((ULONG64)ti.stack_ptr >= (ULONG64)r_info.BaseAddress) && ((ULONG64)(ti.stack_ptr - ti.stack_size) <= ((ULONG64)r_info.BaseAddress + r_info.RegionSize))) {
                        wprintf((LPWSTR)L"Stack: Thread Id 0x%04x\n", ti.thread_id);
                        break;
                    }
                }
            }
            printf("Base address: 0x%p\tAllocation Base: 0x%p\tRegion Size: 0x%08llx\nState: %s\tProtect: %s\t",
                r_info.BaseAddress, r_info.AllocationBase, r_info.RegionSize, get_page_protect(r_info.Protect), get_page_state(r_info.State));
            print_page_type(r_info.Type);

            prev_info_id = info_id;
        }
        printf("\tMatch at address: 0x%p\n", search_ctx.common.matches[i].match_address);
    }
    puts("");
}

static void search_pattern_in_memory(proc_processing_context* ctx) {
    assert(ctx->common.pdata.pattern != nullptr);
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, ctx->pid);
    if (process == NULL) {
        fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
        return;
    }

    if (ctx->common.rdata.redirect) {
        puts(ctx->common.command);
        puts("");
    }

    char proc_name[MAX_PATH];
    if (GetModuleFileNameExA(process, NULL, proc_name, MAX_PATH)) {
        printf("Process name: %s\n\n", proc_name);
    }

    puts("Searching committed memory...");
    puts("\n------------------------------------\n");

    search_context_proc search_ctx{};
    search_ctx.ctx = ctx;
    search_ctx.process = process;
    search_ctx.common.exit_workers = 0;

    search_and_sync(search_ctx);
    print_search_results(search_ctx);

    CloseHandle(process);
}

static void print_hexdump_proc(proc_processing_context* ctx) {
    std::vector<uint8_t> bytes;
    const uint8_t* address = ctx->common.hdata.address;

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, ctx->pid);
    if (process == NULL) {
        fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
        return;
    }

    char proc_name[MAX_PATH];
    if (GetModuleFileNameExA(process, NULL, proc_name, MAX_PATH)) {
        printf("Process name: %s\n\n", proc_name);
    }
    puts("\n------------------------------------\n");

    {
        const char* p = NULL;
        MEMORY_BASIC_INFORMATION info;
        for (p = NULL; VirtualQueryEx(process, p, &info, sizeof(info)) == sizeof(info); p += info.RegionSize) {
            if (info.State == MEM_COMMIT) {
                const size_t region_size = info.RegionSize;
                if ((address >= info.BaseAddress) && (address < ((uint8_t*)info.BaseAddress + region_size))) {
                    size_t bytes_to_read = ctx->common.hdata.num_to_display * ctx->common.hdata.mode;
                    bytes_to_read = _min(bytes_to_read, (region_size - (address - info.BaseAddress)));
                    bytes_to_read = (bytes_to_read / ctx->common.hdata.mode) * ctx->common.hdata.mode;
                    uint8_t* buffer = (uint8_t*)malloc(bytes_to_read);
                    SIZE_T bytes_read;
                    const BOOL res = ReadProcessMemory(process, address, buffer, bytes_to_read, &bytes_read);
                    if (!res || !bytes_read) {
                        fprintf(stderr, "Error reading the memory region.\n");
                        free(buffer);
                        CloseHandle(process);
                        return;
                    }
                    if (bytes_to_read == bytes_read) {
                        ctx->common.hdata.num_to_display = bytes_to_read;
                    } else {
                        ctx->common.hdata.num_to_display = bytes_read / ctx->common.hdata.mode;
                        bytes_to_read = ctx->common.hdata.num_to_display * ctx->common.hdata.mode;
                    }

                    bytes.reserve(bytes_to_read);
                    for (int i = 0; i < bytes_to_read; i++) {
                        bytes.push_back(buffer[i]);
                    }
                    free(buffer);
                    break;
                }
            }
        }
    }

    if (0 == bytes.size()) {
        puts("Address not found in commited memory ranges.");
        CloseHandle(process);
        return;
    }

    print_hexdump(ctx->common.hdata, bytes);

    CloseHandle(process);
}

static void print_help_main() {
    print_help_main_common();
    puts("------------------------------------");
    puts("p <pid>\t\t\t - select PID");
    puts("th?\t\t\t - display heap traversal commands");
    puts("------------------------------------\n");
}

static void print_help_search() {
    print_help_search_common();
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
    puts("lp\t\t\t - list system PIDs");
    puts("------------------------------------\n");
}

static void print_help_info() {
    print_help_info_common();
    puts("------------------------------------\n");
}

static void print_help_traverse_heap() {
    puts("\n------------------------------------");
    puts("th\t\t\t - travers process heaps (slow)");
    puts("the\t\t\t - travers process heaps, calculate entropy (slower)");
    puts("thb\t\t\t - travers process heaps, list heap blocks (extra slow)");
    puts("------------------------------------\n");
}

static input_command parse_command(proc_processing_context *ctx, search_data_info *data, char *pattern) {
    char* cmd = ctx->common.command;
    input_command command;

    const size_t arg_len = strlen(cmd);
    int cmd_length = 1;
    for (; cmd_length < arg_len; cmd_length++) {
        if (cmd[cmd_length] == ' ') break;
    }

    if (cmd[0] == 'p') {
        size_t pid_len = strlen(cmd);
        char* args = skip_to_args(cmd, pid_len);
        if (args == nullptr) {
            fprintf(stderr, "PID missing.\n");
            return c_continue;
        }
        pid_len -= (ptrdiff_t)(args - cmd);
        char* end = NULL;
        const DWORD pid = strtoul(args, &end, is_hex(args, pid_len) ? 16 : 10);
        if (args == end) {
            fprintf(stderr, "[!] Invalid PID.\n");
            command = c_continue;
        } else {
            ctx->pid = pid;
            command = c_test_pid;
        }
    }
    else if (cmd[0] == 'l') {
        if (cmd[1] == '?') {
            return c_help_list;
        }
        if (cmd[1] == 'p' && cmd[2] == 0) {
            command = c_list_pids;
        } else if (cmd[1] == 'M' && cmd[2] == 0) {
            command = c_list_modules;
        } else if (cmd[1] == 't' && cmd[2] == 0) {
            command = c_list_threads;
        } else if (cmd[1] == 'm') {
            if (cmd[2] == 'i') {
                // defaults
                command = c_list_memory_regions_info;
                search_scope_type scope_type = search_scope_type::mrt_all;
                bool stop_parsing = false;
                for (int i = 3; (i < cmd_length) && !stop_parsing; i++) {
                    switch (cmd[i]) {
                    case 'c':
                        command = c_list_memory_regions_info_committed;
                        break;
                    case ':': {
                        if ((i + 1) < cmd_length) {
                            switch (cmd[i + 1]) {
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
                                puts(unknown_command);
                                return c_continue;
                            }
                        }
                        stop_parsing = true;
                        break;
                    }
                    default:
                        fprintf(stderr, unknown_command);
                        return c_continue;
                    }
                }
                ctx->common.pdata.scope_type = scope_type;

            }
            else {
                fprintf(stderr, unknown_command);
                command = c_continue;
            }
        } else {
            fprintf(stderr, unknown_command);
            command = c_continue;
        }
    } else if ((cmd[0] == 't') && (cmd[1] == 'h')) {
        if (cmd[2] == '?') {
            return c_help_traverse_heap;
        }
         if (cmd[2] == 0) {
             command = c_travers_heap;
         } else if (cmd[2] == 'e') {
             command = c_travers_heap_calc_entropy;
         } else if (cmd[2] == 'b') {
             command = c_travers_heap_blocks;
         } else {
             fprintf(stderr, unknown_command);
             command = c_continue;
         }
    } else {
        fprintf(stderr, unknown_command);
        command = c_continue;
    }
    puts("");

    return command;
}

static void execute_command(input_command cmd, proc_processing_context *ctx) {
    const bool pid_required = (cmd > c_help_commands_number) && (cmd != c_list_pids);
    if (pid_required && (ctx->pid == INVALID_ID)) {
        fprintf(stderr, "Select the PID first!\n");
        return;
    }

    switch (cmd) {
    case c_help_main:
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
    case c_help_info:
        print_help_info();
        break;
    case c_help_traverse_heap:
        print_help_traverse_heap();
        break;
    case c_search_pattern :
        try_redirect_output_to_file(&ctx->common);
        search_pattern_in_memory(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_search_pattern_in_registers :
        puts(command_not_implemented);
        puts("");
        break;
    case c_print_hexdump :
        try_redirect_output_to_file(&ctx->common);
        print_hexdump_proc(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_pids:
        try_redirect_output_to_file(&ctx->common);
        list_processes();
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_modules:
        try_redirect_output_to_file(&ctx->common);
        list_process_modules(ctx->pid);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_threads:
        try_redirect_output_to_file(&ctx->common);
        list_process_threads(ctx->pid);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_list_memory_regions_info:
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
    case c_show_info_memory:
        try_redirect_output_to_file(&ctx->common);
        print_memory_info(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_show_info_module:
        try_redirect_output_to_file(&ctx->common);
        print_module_info(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_show_info_thread:
        try_redirect_output_to_file(&ctx->common);
        print_thread_info(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_travers_heap:
        try_redirect_output_to_file(&ctx->common);
        traverse_heap_list(ctx->pid, false, false, output_redirected(&ctx->common));
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_travers_heap_calc_entropy:
        try_redirect_output_to_file(&ctx->common);
        traverse_heap_list(ctx->pid, false, true, output_redirected(&ctx->common));
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_travers_heap_blocks:
        try_redirect_output_to_file(&ctx->common);
        traverse_heap_list(ctx->pid, true, false, output_redirected(&ctx->common));
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    case c_test_pid:
        try_redirect_output_to_file(&ctx->common);
        test_selected_pid(ctx);
        puts("====================================\n");
        redirect_output_to_stdout(&ctx->common);
        break;
    default :
        puts(unknown_command);
        break;
    }
}

int run_process_inspection() {
    puts("\nSelect PID to start inspecting process memory.");
    print_help_main();

    if (g_max_threads == INVALID_THREAD_NUM) { // no -t || --threads cmd arg has been passed
        g_max_threads = MAX_THREAD_NUM; // going to be clamped later
    }

    search_data_info sdata;
    proc_processing_context ctx = { { pattern_data{ nullptr, 0, search_scope_type::mrt_all } }, INVALID_ID };

    char pattern[MAX_PATTERN_LEN];
    char command[MAX_COMMAND_LEN + MAX_ARG_LEN];
    ctx.common.command = command;

    while (1) {
        printf(">: ");
        input_command cmd = parse_command_common(&ctx.common, &sdata, pattern);
        if (cmd == input_command::c_not_set) {
            cmd = parse_command(&ctx, &sdata, pattern);
        } else {
            puts("");
        }
        if (cmd == c_quit_program) {
            return 0;
        } else if (cmd == c_continue) {
            continue;
        }
        execute_command(cmd, &ctx);
    }

    return 0;
}

static int list_processes() {
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        print_error(TEXT("CreateToolhelp32Snapshot (of processes)"));
        return(FALSE);
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        print_error(TEXT("Process32First")); // show cause of failure
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do {
        _tprintf(TEXT("\n\n====================================================="));
        _tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
        _tprintf(TEXT("\n-------------------------------------------------------"));

        // Retrieve the priority class.
        dwPriorityClass = 0;
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL) {
            print_error(TEXT("OpenProcess"));
        } else {
            dwPriorityClass = GetPriorityClass(hProcess);
            if (!dwPriorityClass)
                print_error(TEXT("GetPriorityClass"));
            CloseHandle(hProcess);
        }

        _tprintf(TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID);
        _tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
        _tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
        _tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
        if (dwPriorityClass)
            _tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);

    } while (Process32Next(hProcessSnap, &pe32));
    fprintf(stderr, "\n");
    _tprintf(TEXT("\n================="));
    CloseHandle(hProcessSnap);
    return(TRUE);
}

static int list_process_modules(DWORD dw_pid) {
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    // Take a snapshot of all modules in the specified process.
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dw_pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        print_error(TEXT("CreateToolhelp32Snapshot (of modules)"));
        return(FALSE);
    }

    // Set the size of the structure before using it.
    me32.dwSize = sizeof(MODULEENTRY32);

    // Retrieve information about the first module,
    // and exit if unsuccessful
    if (!Module32First(hModuleSnap, &me32)) {
        print_error(TEXT("Module32First"));  // show cause of failure
        CloseHandle(hModuleSnap);           // clean the snapshot object
        return(FALSE);
    }

    // Now walk the module list of the process,
    // and display information about each module
    printf("====================================");
    do {
        _tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
        _tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
        _tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
        _tprintf(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
        _tprintf(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
        _tprintf(TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
        _tprintf(TEXT("\n     Base size      = 0x%x"), me32.modBaseSize);

    } while (Module32Next(hModuleSnap, &me32));

    puts("\n");

    CloseHandle(hModuleSnap);
    return(TRUE);
}

typedef struct stack_info {
    DWORD_PTR sp;
    SIZE_T size;
} stack_info;

static int get_thread_stack_base(HANDLE hThread, HANDLE process, stack_info *res) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &context);
#ifdef _WIN64
    DWORD_PTR sp = context.Rsp; // Stack pointer for 64-bit
#else
    DWORD_PTR sp = context.Esp; // Stack pointer for 32-bit
#endif

    int stack_base_found = 0;
    MEMORY_BASIC_INFORMATION _info;
    if (VirtualQueryEx(process, (LPCVOID)sp, &_info, sizeof(_info)) == sizeof(_info)) {
        if (_info.State == MEM_COMMIT && _info.Type == MEM_PRIVATE) {
            res->sp = (DWORD_PTR)_info.BaseAddress;
            res->size = _info.RegionSize;
            stack_base_found = 1;
        }
    }

    return stack_base_found;
}

static bool gather_thread_info(DWORD dw_owner_pid, std::vector<thread_info_proc>& thread_info) {
       HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;
    stack_info si = { NULL, 0 };

    // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return (FALSE);

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32)) {
        print_error(TEXT("Thread32First")); // show cause of failure
        CloseHandle(hThreadSnap);
        return (FALSE);
    }

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dw_owner_pid);
    if (process == NULL) {
        fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
        CloseHandle(hThreadSnap);
        return (FALSE);
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do {
        if (te32.th32OwnerProcessID == dw_owner_pid) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
            if (hThread != NULL) {
                if (!get_thread_stack_base(hThread, process, &si)) {
                    puts("Failed acquiring stack base!");
                }
                CloseHandle(hThread);
            }
            thread_info_proc info = { te32.th32ThreadID, te32.tpBasePri, te32.tpDeltaPri, si.sp, si.size };
            thread_info.push_back(info);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(process);
    CloseHandle(hThreadSnap);
}

static int list_process_threads(DWORD dw_owner_pid) {
    std::vector<thread_info_proc> thread_info;

    if (!gather_thread_info(dw_owner_pid, thread_info)) {
        return false;
    }

    printf("====================================");
    for (auto& ti : thread_info) {
        _tprintf(TEXT("\n\n     THREAD ID         = 0x%08X"), ti.thread_id);
        _tprintf(TEXT("\n     Base priority     = %d"), ti.base_prio);
        _tprintf(TEXT("\n     Delta priority    = %d"), ti.delta_prio);
        _tprintf(TEXT("\n     Stack Base        = 0x%p"), ti.stack_ptr);
        _tprintf(TEXT("\n     Stack Size        = 0x%llx"), ti.stack_size);
        _tprintf(TEXT("\n"));
    }
    puts("");

    return true;
}

#define NUM_VALUES 0x100

struct entropy_context {
    size_t freq[NUM_VALUES];
};

static void entropy_init(entropy_context * ctx) {
    memset(ctx->freq, 0, sizeof(ctx->freq));
}

static void entropy_calculate_frequencies(entropy_context* ctx, const uint8_t* data, size_t  size) {
    // Calculate frequencies of each byte
    for (size_t i = 0; i < size; i++) {
        ctx->freq[data[i]]++;
    }
}

static double entropy_compute(entropy_context* ctx, size_t size) {
    double entropy = 0.0;
    const double sz = (double)size;
    for (int i = 0; i < NUM_VALUES; i++) {
        if (ctx->freq[i] != 0) {
            double probability = (double)ctx->freq[i] / sz;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

static int traverse_heap_list(DWORD dw_pid, bool list_blocks, bool calculate_entropy, bool redirected) {
    HEAPLIST32 hl;

    HANDLE hHeapSnap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, dw_pid);

    hl.dwSize = sizeof(HEAPLIST32);

    if (hHeapSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateToolhelp32Snapshot failed (%d)\n", GetLastError());
        return 1;
    }

    if (Heap32ListFirst(hHeapSnap, &hl)) {
        HANDLE process = 0;
        if (calculate_entropy) {
            process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, dw_pid);
            if (process == NULL) {
                fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
                puts("Entropy won't be computed!");
                calculate_entropy = 0;
            }
        }
        puts("====================================");
        entropy_context e_ctx;
        size_t total_size_blocks = 0;
        uint64_t num_blocks = 0;
        uint64_t check_num_results = true;
        do {
            HEAPENTRY32 he;
            ZeroMemory(&he, sizeof(HEAPENTRY32));
            he.dwSize = sizeof(HEAPENTRY32);
            if (Heap32First(&he, dw_pid, hl.th32HeapID)) {
                printf("\n---- Heap ID: 0x%x ----\n", hl.th32HeapID);

                ULONG_PTR start_address = he.dwAddress;
                ULONG_PTR end_address = start_address;
                SIZE_T last_block_size = 0;

                uint8_t* ent_buffer = NULL;
                size_t max_block_size = 0;
                if (calculate_entropy) {
                    entropy_init(&e_ctx);
                }
                do {
                    if (list_blocks) {
                        if (check_num_results && (num_blocks >= TOO_MANY_RESULTS)) {
                            if (too_many_results(num_blocks, redirected, false)) {
                                CloseHandle(hHeapSnap);
                                return -1;
                            }
                            check_num_results = false;
                        }
                        num_blocks++;
                        printf("Start address: 0x%p Block size: 0x%x\n", he.dwAddress, he.dwBlockSize);
                    }

                    if (calculate_entropy) {
                        if (max_block_size < he.dwBlockSize) {
                            max_block_size = he.dwBlockSize;
                            uint8_t* buf = (uint8_t*)realloc(ent_buffer, he.dwBlockSize);
                            if (buf) {
                                ent_buffer = buf;
                            } else {
                                fprintf(stderr, "Buffer allocation faied! Error code: %lu\n", GetLastError());
                                CloseHandle(process);
                                CloseHandle(hHeapSnap);
                                return -1;
                            }
                        }
                        SIZE_T bytes_read;
                        if (ReadProcessMemory(process, (LPCVOID)he.dwAddress, (LPVOID)ent_buffer, he.dwBlockSize, &bytes_read) && (bytes_read == he.dwBlockSize)) {
                            entropy_calculate_frequencies(&e_ctx, ent_buffer, he.dwBlockSize);
                            total_size_blocks += he.dwBlockSize;
                        } else {
                            printf("Start address: 0x%p Block size: 0x%x\n", he.dwAddress, he.dwBlockSize);
                            printf("Failed reading process memory. Error code: %lu\n", GetLastError());
                        }
                    }

                    start_address = _min(start_address, he.dwAddress);
                    if (end_address < he.dwAddress) {
                        end_address = he.dwAddress;
                        last_block_size = he.dwBlockSize;
                    }

                    he.dwSize = sizeof(HEAPENTRY32);
                } while (Heap32Next(&he));
                end_address += last_block_size;
                printf("\nStart Address: 0x%p\n", start_address);
                printf("End Address: 0x%p\n", end_address);
                printf("Size: 0x%llx\n", ptrdiff_t(end_address - start_address));
                if (calculate_entropy) {
                    const double entropy = entropy_compute(&e_ctx, total_size_blocks);
                    printf("Entropy: %.2F\n", entropy);
                    free(ent_buffer);
                }
            }
            hl.dwSize = sizeof(HEAPLIST32);
        } while (Heap32ListNext(hHeapSnap, &hl));

        if (calculate_entropy) {
            CloseHandle(process);
        }
    } else {
        printf("Cannot list first heap (%d)\n", GetLastError());
    }

    puts("");

    CloseHandle(hHeapSnap);

    return 0;
}

static void list_memory_regions_info(const proc_processing_context* ctx, bool show_commited) {
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, ctx->pid);
    if (process == NULL) {
        fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
        return;
    }

    const bool redirected = output_redirected(&ctx->common);

    const char* p = NULL;
    MEMORY_BASIC_INFORMATION r_info;
    uint64_t num_regions = 0;
    uint64_t check_num_results = true;
    const bool scoped_search = ctx->common.pdata.scope_type != search_scope_type::mrt_all;

    std::vector<thread_info_proc> thread_info;
    if ((ctx->common.pdata.scope_type == search_scope_type::mrt_stack) || (ctx->common.pdata.scope_type == search_scope_type::mrt_other)) {
        gather_thread_info(ctx->pid, thread_info);
    }

    puts("====================================\n");
    for (p = NULL; VirtualQueryEx(process, p, &r_info, sizeof(r_info)) == sizeof(r_info); p += r_info.RegionSize) {
        if (show_commited && (r_info.State != MEM_COMMIT)) {
            continue;
        }

        if (scoped_search && !identify_memory_region_type(ctx->common.pdata.scope_type, r_info, thread_info)) {
            continue;
        }

        if (check_num_results && (num_regions >= TOO_MANY_RESULTS)) {
            if (too_many_results(num_regions, redirected, false)) {
                CloseHandle(process);
                return;
            }
            check_num_results = false;
        }
        num_regions++;
        if (r_info.Type == MEM_IMAGE) {
            char module_name[MAX_PATH];
            if (GetModuleFileNameExA(process, (HMODULE)r_info.AllocationBase, module_name, MAX_PATH)) {
                printf("Module name: %s\n", module_name);
            }
        }
        printf("Base address: 0x%p\tAllocation Base: 0x%p\tRegion Size: 0x%08llx\nState: %s\tProtect: %s\t",
            r_info.BaseAddress, r_info.AllocationBase, r_info.RegionSize, get_page_protect(r_info.Protect), get_page_state(r_info.State));
        print_page_type(r_info.Type);
        puts("");
    }
    puts("");
    printf("*** Number of Memory Info Entries: %llu ***\n\n", num_regions);

    CloseHandle(process);
}

static void print_error(TCHAR const* msg) {
    DWORD eNum;
    TCHAR sysMsg[256];
    TCHAR* p;

    eNum = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, eNum,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        sysMsg, 256, NULL);

    // Trim the end of the line and terminate it with a null
    p = sysMsg;
    while ((*p > 31) || (*p == 9))
        ++p;
    do { *p-- = 0; } while ((p >= sysMsg) &&
        ((*p == '.') || (*p < 33)));

    // Display the message
    _ftprintf(stderr, TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

static bool test_selected_pid(proc_processing_context* ctx) {
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, ctx->pid);
    if (process == NULL) {
        ctx->pid = INVALID_ID;
        fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
        return false;
    }

    char proc_name[MAX_PATH];
    if (GetModuleFileNameExA(process, NULL, proc_name, MAX_PATH)) {
        printf("Process name: %s\n", proc_name);
    }

    SIZE_T min_working_set, max_working_set;
    DWORD flags;
    GetProcessWorkingSetSizeEx(process, &min_working_set, &max_working_set, &flags);

    printf("Working set: min - 0x%llx bytes | max - 0x%llx bytes\n", min_working_set, max_working_set);

    APP_MEMORY_INFORMATION mem_info;
    if (GetProcessInformation(process, ProcessAppMemoryInfo, &mem_info, sizeof(mem_info))) {
        printf("Available Commit:\t\t 0x%08llx bytes\n", mem_info.AvailableCommit);
        printf("Private Commit Usage:\t\t 0x%08llx bytes\n", mem_info.PrivateCommitUsage);
        printf("Peak Private Commit Usage:\t 0x%08llx bytes\n", mem_info.PeakPrivateCommitUsage);
        printf("Total Commit Usage:\t\t 0x%08llx bytes\n", mem_info.TotalCommitUsage);   
    }
    puts("");

    CloseHandle(process);
    return true;
}

static DWORD is_on_stack(const proc_processing_context* ctx, const MEMORY_BASIC_INFORMATION* r_info) {
    std::vector<thread_info_proc> thread_info;
    gather_thread_info(ctx->pid, thread_info);
    DWORD tid = INVALID_ID;

    for (const auto& ti : thread_info) {
        if (((ULONG64)ti.stack_ptr >= (ULONG64)r_info->AllocationBase) && ((ULONG64)(ti.stack_ptr - ti.stack_size) <= ((ULONG64)r_info->BaseAddress + r_info->RegionSize))) {
            wprintf((LPWSTR)L"Stack: Thread Id 0x%04x\n", ti.thread_id);
            break;
        }
    }

    return tid;
}

static void print_region_flags(const WIN32_MEMORY_REGION_INFORMATION* flags) {
    printf("Range Flags: ");
    if (flags->Private) printf("Private ");
    if (flags->MappedDataFile) printf("MappedDataFile ");
    if (flags->MappedImage) printf("MappedImage ");
    if (flags->MappedPageFile) printf("MappedPageFile ");
    if (flags->MappedPhysical) printf("MappedPhysical ");
    if (flags->DirectMapped) printf("DirectMapped ");
    printf("\n");
}

static void print_memory_info(const proc_processing_context* ctx) {
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, ctx->pid);
    if (process == NULL) {
        fprintf(stderr, "Failed opening the process. Error code: %lu\n", GetLastError());
        return;
    }

    MEMORY_BASIC_INFORMATION r_info;
    if (VirtualQueryEx(process, ctx->common.info_ctx.memory_address, &r_info, sizeof(r_info)) != sizeof(r_info)) {
        fprintf(stderr, "Error virtual query ex failed.\n");
        CloseHandle(process);
        return;
    }

    WIN32_MEMORY_REGION_INFORMATION mem_info = { 0 };
    SIZE_T return_length = 0;
    BOOL status = QueryVirtualMemoryInformation
                        (process, ctx->common.info_ctx.memory_address, MemoryRegionInfo, &mem_info, sizeof(mem_info), &return_length);

    puts("====================================\n");
    if (r_info.Type == MEM_IMAGE) {
        char module_name[MAX_PATH];
        if (GetModuleFileNameExA(process, (HMODULE)r_info.AllocationBase, module_name, MAX_PATH)) {
            printf("Module name: %s\n", module_name);
        }
    } else if (r_info.Type == MEM_PRIVATE) {
       DWORD tid = is_on_stack(ctx, &r_info);
       if (tid != INVALID_ID) {
           wprintf((LPWSTR)L"Stack: Thread Id 0x%04x\n", tid);
       }
    }
    printf("Base address: 0x%p\tAllocation Base: 0x%p\tRegion Size: 0x%08llx\nState: %s\tProtect: %s\t",
        r_info.BaseAddress, r_info.AllocationBase, r_info.RegionSize, get_page_protect(r_info.Protect), get_page_state(r_info.State));
    print_page_type(r_info.Type);
    if (status) {
        printf("Range Alloc Size: 0x%llx bytes\n", (uint64_t)mem_info.RegionSize);
        printf("Range Commit Size: 0x%llx bytes\n", (uint64_t)mem_info.CommitSize);
        print_region_flags(&mem_info);
    }
    CloseHandle(process);
}

static void print_module_info(const proc_processing_context* ctx) {
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    // Take a snapshot of all modules in the specified process.
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ctx->pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        print_error(TEXT("CreateToolhelp32Snapshot (of modules)"));
        return;
    }

    // Set the size of the structure before using it.
    me32.dwSize = sizeof(MODULEENTRY32);

    // Retrieve information about the first module,
    // and exit if unsuccessful
    if (!Module32First(hModuleSnap, &me32)) {
        print_error(TEXT("Module32First"));  // show cause of failure
        CloseHandle(hModuleSnap);           // clean the snapshot object
        return;
    }

    // Now walk the module list of the process,
    // and display information about each module
    printf("====================================");
    do {
        if (nullptr == wcsstr(me32.szModule, ctx->common.info_ctx.module_name)) {
            continue;
        }

        _tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
        _tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
        _tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
        _tprintf(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
        _tprintf(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
        _tprintf(TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
        _tprintf(TEXT("\n     Base size      = 0x%x"), me32.modBaseSize);

        break;
    } while (Module32Next(hModuleSnap, &me32));

    puts("\n");

    CloseHandle(hModuleSnap);
    return;
}

static void print_thread_info(const proc_processing_context* ctx) {
    std::vector<thread_info_proc> thread_info;

    if (!gather_thread_info(ctx->pid, thread_info)) {
        return;
    }

    printf("====================================");
    for (auto& ti : thread_info) {
        if (ti.thread_id != ctx->common.info_ctx.tid) {
            continue;
        }
        _tprintf(TEXT("\n\n     THREAD ID         = 0x%08X"), ti.thread_id);
        _tprintf(TEXT("\n     Base priority     = %d"), ti.base_prio);
        _tprintf(TEXT("\n     Delta priority    = %d"), ti.delta_prio);
        _tprintf(TEXT("\n     Stack Base        = 0x%p"), ti.stack_ptr);
        _tprintf(TEXT("\n     Stack Size        = 0x%llx"), ti.stack_size);
        _tprintf(TEXT("\n"));
        break;
    }
    puts("");
}