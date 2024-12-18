#include "common.h"

extern int run_process_inspection();
extern int run_dump_inspection();

int main(int argc, const char** argv) {
    if (!check_architecture_rt()) {
        puts("Only x86-64 architecture is supported at the moment!");
        return 1;
    }

    if (g_inspection_mode == inspection_mode::im_dump) {
        g_max_threads = IDEAL_THREAD_DUMP;
    } else {
        g_max_threads = MAX_THREADS;
    }

    if (!parse_cmd_args(argc, argv)) {
        return 0;
    }

    int result = 0;
    if (g_inspection_mode == inspection_mode::im_process) {
        result = run_process_inspection();
    } else if (g_inspection_mode == inspection_mode::im_dump) {
        result = run_dump_inspection();
    } else {
        assert(false);
    }

    return result;
}