#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile u32 cpu_count;

#define MAX_CPUS 20		// TODO: make this dynamically change to machine's CPU count
#define MAX_PROCESSES 1024	// TODO: put a more realistic upper bound on process count
#define FAST_SLICE 50000000ULL

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

u64 nr_finished_fast, nr_sent_to_slow;

bool pid_exists(pid_t pid_to_check) {
	u8 *value = bpf_map_lookup_elem(&slow_pids, &pid_to_check);
    return value != NULL;
}

s32 BPF_STRUCT_OPS(split_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	// bpf_printk("split_select_cpu: pid=%d, prev_cpu=%d, wake_flags=%llu\n", p->pid, prev_cpu, wake_flags);
	if (pid_exists(p->pid)) {
		bpf_printk("existed in pid list (select_cpu func)");
		// TODO: make this use the cpu maps
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
		return 0;
	}
	bpf_printk("didn't exist in pid list (select_cpu func)");
	// TODO: make this use the cpu maps
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, FAST_SLICE, 0);
	return 1;
}

void BPF_STRUCT_OPS(split_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (enq_flags & SCX_ENQ_LAST || pid_exists(p->pid)) {
		// bpf_printk("%d existed in pid list (enqueue func)", p->pid);
		// TODO: make this use the cpu maps
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | 0, SCX_SLICE_INF, 0);
	} else {
		// bpf_printk("%d didn't exist in pid list (enqueue func)", p->pid);
		// TODO: make this use the cpu maps
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | 1, FAST_SLICE, 0);
	}
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
		__sync_fetch_and_add(&nr_sent_to_slow, 1);
	}
}

SCX_OPS_DEFINE(split_ops,
	       .select_cpu		= (void *)split_select_cpu,
	       .enqueue			= (void *)split_enqueue,
		   .tick			= (void *)split_tick,
		   .init			= (void *)split_init,
		   .exit			= (void *)split_exit,
	       .name			= "split",
		   .flags			= SCX_OPS_SWITCH_PARTIAL | SCX_OPS_ENQ_LAST
           );
