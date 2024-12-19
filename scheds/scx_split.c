#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_split.bpf.skel.h"

static bool verbose;
static volatile int exit_req;


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
    exit_req = 1;
}


int main(int argc, char **argv) {
    struct scx_split *skel;
    struct bpf_link *link;
    __u32 opt;
    __u64 ecode;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    restart:
        skel = SCX_OPS_OPEN(split_ops, scx_split);
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch(opt) {
            case 'v':
                verbose = true;
            break;
            default:
                fprintf(stderr, "Wrong inputs");
        }
    }

    skel->rodata->cpu_count = libbpf_num_possible_cpus();

    SCX_OPS_LOAD(skel, split_ops, scx_split, uei);
    link = SCX_OPS_ATTACH(skel, split_ops, scx_split);
    printf("scx_split scheduler has started...\n");
    fflush(stdout);

    while (!exit_req && !UEI_EXITED(skel, uei)) {
        printf("total selected: %lu\n", skel->bss->nr_total_selected);
        printf("total enqueued: %lu\n", skel->bss->nr_total_enqueued);
        printf("sent to slow: %lu\n", skel->bss->nr_sent_to_slow);
        printf("selected_for_fast: %lu\n", skel->bss->nr_selected_for_fast);
        printf("enqueued_for_fast: %lu\n", skel->bss->nr_enqueued_for_fast);
        printf("####################\n\n");

        sleep(3);
    }

    bpf_link__destroy(link);
    ecode = UEI_REPORT(skel, uei);
    scx_split__destroy(skel);

    if (UEI_ECODE_RESTART(ecode))
        goto restart;

    printf("scx_split exiting with code 0\n");
    return 0;
}