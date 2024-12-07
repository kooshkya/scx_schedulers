/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A scheduler with every callback defined, with printk statements for debugging.
 *
 * Copyright (c) 2024 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024 David Vernet <dvernet@meta.com>
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

const volatile bool select_cpu_mute;
const volatile bool enqueue_mute;
const volatile bool dequeue_mute;
const volatile bool dispatch_mute;
const volatile bool runnable_mute;
const volatile bool running_mute;
const volatile bool stopping_mute;
const volatile bool quiescent_mute;
const volatile bool yield_mute;
const volatile bool core_sched_before_mute;
const volatile bool set_weight_mute;
const volatile bool set_cpumask_mute;
const volatile bool update_idle_mute;
const volatile bool cpu_acquire_mute;
const volatile bool cpu_release_mute;
const volatile bool cpu_online_mute;
const volatile bool cpu_offline_mute;
const volatile bool init_task_mute;
const volatile bool enable_mute;
const volatile bool exit_task_mute;
const volatile bool disable_mute;
const volatile bool successful_dispatch_mute;

s32 BPF_STRUCT_OPS(maximal_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	if (!select_cpu_mute)
		bpf_printk("select_cpu: pid=%d, prev_cpu=%d, wake_flags=%llu\n", p->pid, prev_cpu, wake_flags);
	return prev_cpu;
}

void BPF_STRUCT_OPS(maximal_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (!enqueue_mute)
		bpf_printk("enqueue: pid=%d, enq_flags=%llu\n", p->pid, enq_flags);
	scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(maximal_dequeue, struct task_struct *p, u64 deq_flags)
{
	if (!dequeue_mute)
		bpf_printk("dequeue: pid=%d, deq_flags=%llu\n", p->pid, deq_flags);
}

void BPF_STRUCT_OPS(maximal_dispatch, s32 cpu, struct task_struct *prev)
{
    if (!dispatch_mute)
		bpf_printk("dispatch: cpu=%d, prev=%p\n", cpu, prev);
}

void BPF_STRUCT_OPS(maximal_runnable, struct task_struct *p, u64 enq_flags)
{
	if (!runnable_mute)
		bpf_printk("runnable: pid=%d, enq_flags=%llu\n", p->pid, enq_flags);
}

void BPF_STRUCT_OPS(maximal_running, struct task_struct *p)
{
	if (!running_mute)
		bpf_printk("running: pid=%d\n", p->pid);
}

void BPF_STRUCT_OPS(maximal_stopping, struct task_struct *p, bool runnable)
{
	if (!stopping_mute)
		bpf_printk("stopping: pid=%d, runnable=%d\n", p->pid, runnable);
}

void BPF_STRUCT_OPS(maximal_quiescent, struct task_struct *p, u64 deq_flags)
{
	if (!quiescent_mute)
		bpf_printk("quiescent: pid=%d, deq_flags=%llu\n", p->pid, deq_flags);
}

bool BPF_STRUCT_OPS(maximal_yield, struct task_struct *from, struct task_struct *to)
{
	// if (!yield_mute)
    // bpf_printk("yield: from_pid=%d, to_pid=%d\n", from->pid, to->pid);
	return false;
}

bool BPF_STRUCT_OPS(maximal_core_sched_before, struct task_struct *a, struct task_struct *b)
{
	if (!core_sched_before_mute)
		bpf_printk("core_sched_before: pid_a=%d, pid_b=%d\n", a->pid, b->pid);
	return false;
}

void BPF_STRUCT_OPS(maximal_set_weight, struct task_struct *p, u32 weight)
{
	if (!set_weight_mute)
		bpf_printk("set_weight: pid=%d, weight=%u\n", p->pid, weight);
}

void BPF_STRUCT_OPS(maximal_set_cpumask, struct task_struct *p, const struct cpumask *cpumask)
{
	if (!set_cpumask_mute)
		bpf_printk("set_cpumask: pid=%d\n", p->pid);  // cpumask is a complex type, so keeping it simple here
}

void BPF_STRUCT_OPS(maximal_update_idle, s32 cpu, bool idle)
{
	if (!update_idle_mute)
		bpf_printk("update_idle: cpu=%d, idle=%d\n", cpu, idle);
}

void BPF_STRUCT_OPS(maximal_cpu_acquire, s32 cpu, struct scx_cpu_acquire_args *args)
{
	if (!cpu_acquire_mute)
		bpf_printk("cpu_acquire: cpu=%d\n", cpu);
}

void BPF_STRUCT_OPS(maximal_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	if (!cpu_release_mute)
		bpf_printk("cpu_release: cpu=%d\n", cpu);
}

void BPF_STRUCT_OPS(maximal_cpu_online, s32 cpu)
{
	if (!cpu_online_mute)
		bpf_printk("cpu_online: cpu=%d\n", cpu);
}

void BPF_STRUCT_OPS(maximal_cpu_offline, s32 cpu)
{
	if (!cpu_offline_mute)
		bpf_printk("cpu_offline: cpu=%d\n", cpu);
}

s32 BPF_STRUCT_OPS(maximal_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	if (!init_task_mute)
		bpf_printk("init_task: pid=%d, policy=%d\n", p->pid, p->policy);
	return 0;
}

void BPF_STRUCT_OPS(maximal_enable, struct task_struct *p)
{
	if (!enable_mute)
		bpf_printk("enable: pid=%d and new policy=%d\n", p->pid, p->policy);
}

void BPF_STRUCT_OPS(maximal_exit_task, struct task_struct *p, struct scx_exit_task_args *args)
{
	if (!exit_task_mute)
		bpf_printk("exit_task: pid=%d\n", p->pid);
}

void BPF_STRUCT_OPS(maximal_disable, struct task_struct *p)
{
	if (!disable_mute)
		bpf_printk("disable: pid=%d\n", p->pid);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(maximal_init)
{
	bpf_printk("init called\n");
	return 0;
}

void BPF_STRUCT_OPS(maximal_exit, struct scx_exit_info *info)
{
	bpf_printk("exit called\n");
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(maximal_ops,
	.select_cpu		= (void*)maximal_select_cpu,
	.enqueue		= (void*)maximal_enqueue,
	.dequeue		= (void*)maximal_dequeue,
	.dispatch		= (void*)maximal_dispatch,
	.runnable		= (void*)maximal_runnable,
	.running		= (void*)maximal_running,
	.stopping		= (void*)maximal_stopping,
	.quiescent		= (void*)maximal_quiescent,
	.yield			= (void*)maximal_yield,
	.core_sched_before	= (void*)maximal_core_sched_before,
	.set_weight		= (void*)maximal_set_weight,
	.set_cpumask		= (void*)maximal_set_cpumask,
	.update_idle		= (void*)maximal_update_idle,
	.cpu_acquire		= (void*)maximal_cpu_acquire,
	.cpu_release		= (void*)maximal_cpu_release,
	.cpu_online		= (void*)maximal_cpu_online,
	.cpu_offline		= (void*)maximal_cpu_offline,
	.init_task		= (void*)maximal_init_task,
	.enable			= (void*)maximal_enable,
	.exit_task		= (void*)maximal_exit_task,
	.disable		= (void*)maximal_disable,
	.init			= (void*)maximal_init,
	.exit			= (void*)maximal_exit,
	.name			= "maximal",
    .flags          = SCX_OPS_SWITCH_PARTIAL);
