/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

// #include <vmlinux/vmlinux-v6.10-rc2-g1edab907b57d.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
const volatile bool running_stopping_mute;
const volatile bool acquire_release_mute;
const volatile bool tick_mute;
const volatile bool all_mute;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dispatch_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could
 * just use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bpf_printk("simple_select_cpu: pid=%d, prev_cpu=%d, wake_flags=%llu\n", p->pid, prev_cpu, wake_flags);
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	bpf_printk("simple_enqueue: pid=%d, enq_flags=%llu\n", p->pid, enq_flags);
	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(test_dequeue, struct task_struct *p, u64 deq_flags)
{
	bpf_printk("simple dequeue: pid=%d, enq_flags=%llu\n", p->pid, deq_flags);
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	bool result = scx_bpf_consume(SHARED_DSQ);
	if (result) {
		bpf_printk("successful simple_dispatch: cpu=%d, prev=%p\n", cpu, prev);
	}
}


void BPF_STRUCT_OPS(simple_runnable, struct task_struct *p, u64 enq_flags)
{
	bpf_printk("simple_runnable: pid=%d\n", p->pid);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	if (!all_mute && !running_stopping_mute)
		bpf_printk("simple_running: pid=%d on cpu=%d\n", p->pid, scx_bpf_task_cpu(p));
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	if (!all_mute && !running_stopping_mute)
		bpf_printk("simple_stopping: pid=%d, runnable=%d\n", p->pid, runnable);
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	bpf_printk("simple_enable: p=%p\n", p);
	p->scx.dsq_vtime = vtime_now;
}

void BPF_STRUCT_OPS(simple_tick, struct task_struct *p)
{
	if (!all_mute && !tick_mute)
		bpf_printk("ticking: p->scx.slice=%llu", p->scx.slice);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	bpf_printk("simple_init\n");
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	bpf_printk("simple_exit: ei=%p\n", ei);
	UEI_RECORD(uei, ei);
}

void BPF_STRUCT_OPS(test_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args) 
{
	if (!all_mute && !acquire_release_mute)
		bpf_printk("Acquiring CPU %d", cpu);
}

void BPF_STRUCT_OPS(test_cpu_release, s32 cpu, struct scx_cpu_release_args *args) 
{
	if (!all_mute && !acquire_release_mute)
		bpf_printk("Released CPU %d to pid %d of class %d", cpu, args->task->pid, args->reason);
}

SCX_OPS_DEFINE(test_ops,
	       .select_cpu		= (void *)simple_select_cpu,
	       .enqueue			= (void *)simple_enqueue,
		   .dequeue			= (void *)test_dequeue,
	       .dispatch		= (void *)simple_dispatch,
		   .runnable		= (void *)simple_runnable,
	       .running			= (void *)simple_running,
	       .stopping		= (void *)simple_stopping,
		   .tick			= (void *)simple_tick,
	       .enable			= (void *)simple_enable,
		   .cpu_acquire		= (void *)test_cpu_acquire,
		   .cpu_release		= (void *)test_cpu_release,
	       .init			= (void *)simple_init,
	       .exit			= (void *)simple_exit,
	       .name			= "test",
		   .flags			= SCX_OPS_SWITCH_PARTIAL);
