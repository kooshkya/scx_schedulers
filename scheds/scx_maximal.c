/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_maximal.bpf.skel.h"

#define NUM_VOLATILE_BOOLEANS 22

static bool verbose;
static volatile int exit_req;

/* Function to handle libbpf print levels */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/* Signal handler for graceful exit */
static void sigint_handler(int sig)
{
	exit_req = 1;
}

/* Function to read the volatile bools from an input file */
static int read_volatile_bools_from_file(const char *filename, bool *bools, int num_bools)
{
	FILE *file = fopen(filename, "r");
	if (!file) {
		perror("Failed to open input file");
		return -1;
	}

	char line[16];
    int count = 0;

    while (count < num_bools) {
        if (!fgets(line, sizeof(line), file)) {
            break;
        }

        char first_five[6];
        strncpy(first_five, line, 5);
        first_five[5] = '\0';

        if (strncmp(first_five, "true", 4) == 0) {
            bools[count] = true;
        } else if (strncmp(first_five, "false", 5) == 0) {
            bools[count] = false;
        } else {
            fprintf(stderr, "Invalid value in file at line %d: %s", count + 1, line);
            return -1;
        }

        count++;

        while (fgetc(file) != '\n' && !feof(file));
    }

	fclose(file);

	if (count != num_bools) {
		fprintf(stderr, "Input file must contain exactly %d lines\n", num_bools);
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct scx_maximal *skel;
	struct bpf_link *link;
	__u64 ecode;
	const char *input_file = "./mute_configs.txt";
	bool volatile_bools[NUM_VOLATILE_BOOLEANS];

	for (int i = 0; i < NUM_VOLATILE_BOOLEANS; i++) {
		volatile_bools[i] = true;
	}

	if (input_file && read_volatile_bools_from_file(input_file, volatile_bools, NUM_VOLATILE_BOOLEANS) != 0) {
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

restart:
	skel = SCX_OPS_OPEN(maximal_ops, scx_maximal);
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->rodata->select_cpu_mute = volatile_bools[0];
	skel->rodata->enqueue_mute = volatile_bools[1];
	skel->rodata->dequeue_mute = volatile_bools[2];
	skel->rodata->dispatch_mute = volatile_bools[3];
	skel->rodata->runnable_mute = volatile_bools[4];
	skel->rodata->running_mute = volatile_bools[5];
	skel->rodata->stopping_mute = volatile_bools[6];
	skel->rodata->quiescent_mute = volatile_bools[7];
	skel->rodata->yield_mute = volatile_bools[8];
	skel->rodata->core_sched_before_mute = volatile_bools[9];
	skel->rodata->set_weight_mute = volatile_bools[10];
	skel->rodata->set_cpumask_mute = volatile_bools[11];
	skel->rodata->update_idle_mute = volatile_bools[12];
	skel->rodata->cpu_acquire_mute = volatile_bools[13];
	skel->rodata->cpu_release_mute = volatile_bools[14];
	skel->rodata->cpu_online_mute = volatile_bools[15];
	skel->rodata->cpu_offline_mute = volatile_bools[16];
	skel->rodata->init_task_mute = volatile_bools[17];
	skel->rodata->enable_mute = volatile_bools[18];
	skel->rodata->exit_task_mute = volatile_bools[19];
	skel->rodata->disable_mute = volatile_bools[20];
	skel->rodata->successful_dispatch_mute = volatile_bools[21];

	SCX_OPS_LOAD(skel, maximal_ops, scx_maximal, uei);
	link = SCX_OPS_ATTACH(skel, maximal_ops, scx_maximal);

	while (!exit_req && !UEI_EXITED(skel, uei)) {}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_maximal__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;

	return 0;
}
