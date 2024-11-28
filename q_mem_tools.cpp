#include "common.h"
#include "process_mem_tool.h"
#include "dump_mem_tool.h"

int main(int argc, const char** argv) {
    if (!check_architecture_rt()) {
        puts("Only x86-64 architecture is supported at the moment!");
        return 1;
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