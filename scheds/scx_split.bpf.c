#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile u32 cpu_count;

#define MAX_CPUS 20		// TODO: make this dynamically change to machine's CPU count
#define MAX_PROCESSES 1024	// TODO: put a more realistic upper bound on process count

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);
    __type(value, u8);
    __uint(max_entries, MAX_PROCESSES);
} slow_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, s32);
    __uint(max_entries, MAX_CPUS);
} cpu_group_fast SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, s32);
    __uint(max_entries, MAX_CPUS);
} cpu_group_slow SEC(".maps");

int fast_group_size;
int slow_group_size;
int pid_array_size;

bool pid_exists(pid_t pid_to_check) {
	u8 *value = bpf_map_lookup_elem(&slow_pids, &pid_to_check);
    return value != NULL;
}

s32 BPF_STRUCT_OPS(split_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bpf_printk("split_select_cpu: pid=%d, prev_cpu=%d, wake_flags=%llu\n", p->pid, prev_cpu, wake_flags);
	if (pid_exists(p->pid)) {
		bpf_printk("existed in pid list");
		struct bpf_cpumask * mask = bpf_cpumask_create();
		if (!mask) {
			bpf_printk("ERROR: couldn't create cpumask");
			return 0;
		}
		// TODO: make this use the cpu map
		bpf_cpumask_set_cpu(0, mask);
		bpf_cpumask_set_cpu(1, mask);
		bpf_cpumask_set_cpu(2, mask);
		bpf_cpumask_set_cpu(3, mask);
		s32 idle = scx_bpf_pick_idle_cpu((struct cpumask*)mask, 0);
		bpf_cpumask_release(mask);
		if (idle >= 0) {
			bpf_printk("dispatched to cpu %d\n", idle);
			scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
			return idle;
		}
	} else {
		bpf_printk("didn't exist in pid list");
		struct bpf_cpumask * mask = bpf_cpumask_create();
		if (!mask) {
			bpf_printk("ERROR: couldn't create cpumask");
			return 0;
		}
		// TODO: make this use the cpu map
		bpf_cpumask_set_cpu(4, mask);
		bpf_cpumask_set_cpu(5, mask);
		bpf_cpumask_set_cpu(6, mask);
		bpf_cpumask_set_cpu(7, mask);
		s32 idle = scx_bpf_pick_idle_cpu((struct cpumask*)mask, 0);
		bpf_cpumask_release(mask);
		if (idle >= 0) {
			bpf_printk("dispatched to cpu %d\n", idle);
			scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
			return idle;
		}
	}
	bpf_printk("resort to 0");
	return 0;
}

int setup_cpu_groups(void) {
	// TODO: make CPU distribution logic more sophisticated
    s32 fast_cpus[MAX_CPUS];
    s32 slow_cpus[MAX_CPUS];

	for (int i = 0; i < MAX_CPUS; i++) {
    	fast_cpus[i] = -1;
		slow_cpus[i] = -1;
	}

	u32 mid = cpu_count / 3;

	for (int i = 0; i < MAX_CPUS; i++) {
		if (i < mid)
			fast_cpus[i] = i;
	}

	for (int i = 0; i < MAX_CPUS; i++) {
		if (i < cpu_count - mid) {
			slow_cpus[i] = i + mid;
		}
	}

    for (int i = 0; i < MAX_CPUS; i++) {
		if (fast_cpus[i] == -1)
			break;
		bpf_printk("setting cpu %d for fast", fast_cpus[i]);
		fast_group_size++;
		u32 key = i;
		if (bpf_map_update_elem(&cpu_group_fast, &key, &fast_cpus[i], BPF_ANY)) {
			return -1;
		}
    }

    for (int i = 0; i < MAX_CPUS; i++) {
		if (slow_cpus[i] == -1)
			break;
		bpf_printk("setting cpu %d for slow", slow_cpus[i]);
		slow_group_size++;
		u32 key = i;
		if(bpf_map_update_elem(&cpu_group_slow, &key, &slow_cpus[i], BPF_ANY)) {
			return -1;
		}
    }
	return 0;
}

s32 BPF_STRUCT_OPS(split_init)
{
	bpf_printk("%d\n", cpu_count);
	if (setup_cpu_groups()) {
		return -1;
	}
	return 0;
}

s32 BPF_STRUCT_OPS(split_exit)
{
	return 0;
}

void BPF_STRUCT_OPS(split_tick, struct task_struct *p)
{
	if (p->scx.slice == 0 && !pid_exists(p->pid)) {
		u8 value = 1;
		pid_t pid = p->pid;
    	bpf_map_update_elem(&slow_pids, &pid, &value, BPF_ANY);		// TODO: add error checking to this
		bpf_printk("the pid %d has moved to slow group\n", p->pid);
	}
}

SCX_OPS_DEFINE(split_ops,
	       .select_cpu		= (void *)split_select_cpu,
		   .tick			= (void *)split_tick,
		   .init			= (void *)split_init,
		   .exit			= (void *)split_exit,
	       .name			= "split",
		   .flags			= SCX_OPS_SWITCH_PARTIAL
           );
