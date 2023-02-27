#include <asm/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
#include <linux/bpf.h>

//#define USER_STACKS
//#define KERNEL_STACKS
struct syscall_data_t {
    u32 pid;
    u32 tgid;
    unsigned char type;
    char strBuf[256];
    u64 syscallId;
    u64 pc;
    u64 lr;
    u64 ret;
    __s64 ret2;
    u64 args[6];
    u64 start_ns;
    u64 duration_ns;
#ifdef USER_STACKS
    int user_stack_id;
#endif
#ifdef KERNEL_STACKS
    int kernel_stack_id;
    u64 kernel_ip;
#endif
};
struct entry_t {
    u64 start_ns;
#ifdef USER_STACKS
    int user_stack_id;
#endif
#ifdef KERNEL_STACKS
    int kernel_stack_id;
    u64 kernel_ip;
#endif
};

BPF_PERF_OUTPUT(syscall_events);

struct input_data_t {
    bool is32;
    bool useFilter;
};
BPF_HASH(input, u32, struct input_data_t);

struct sysdesc_t {
    u32 stringMask;
};
BPF_HASH(sysdesc, u32, struct sysdesc_t);

BPF_HASH(sysfilter, u32, u8);

BPF_HASH(tids_filter, u32, u32);

BPF_HASH(entryinfo, u32, struct entry_t);

#if defined(USER_STACKS) || defined(KERNEL_STACKS)
BPF_STACK_TRACE(stacks, 2048);
#endif

RAW_TRACEPOINT_PROBE(sys_enter){

    u32 tid = bpf_get_current_pid_tgid();    
    PROCESS_FILTER

    //ctx->args[0]指向的内容才是真正的寄存器
    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    unsigned long syscall_id = ctx->args[1];

    struct entry_t *entry = entryinfo.lookup(&tid);
    if(!entry){
        struct entry_t new_entry = {};
        entryinfo.update(&tid, &new_entry);
        entry = &new_entry;
    }
    
    entry->start_ns = bpf_ktime_get_ns();
    #ifdef USER_STACKS
    entry->user_stack_id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
    #endif

    #ifdef KERNEL_STACKS
    entry->kernel_stack_id = stacks.get_stackid(ctx, 0);

    if (entry->kernel_stack_id >= 0) {
        u64 ip = PT_REGS_IP(ctx);
        u64 page_offset;

        // if ip isn't sane, leave key ips as zero for later checking
    #if defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE)
        // x64, 4.16, ..., 4.11, etc., but some earlier kernel didn't have it
        page_offset = __PAGE_OFFSET_BASE;
    #elif defined(CONFIG_X86_64) && defined(__PAGE_OFFSET_BASE_L4)
        // x64, 4.17, and later
    #if defined(CONFIG_DYNAMIC_MEMORY_LAYOUT) && defined(CONFIG_X86_5LEVEL)
        page_offset = __PAGE_OFFSET_BASE_L5;
    #else
        page_offset = __PAGE_OFFSET_BASE_L4;
    #endif
    #else
        // earlier x86_64 kernels, e.g., 4.6, comes here
        // arm64, s390, powerpc, x86_32
        page_offset = PAGE_OFFSET;
    #endif

        if (ip > page_offset) {
            entry->kernel_ip = ip;
        }
    }
    #endif

    struct syscall_data_t data = {0};

    u32 key0 = 0;
    struct input_data_t *inputParams = input.lookup(&key0);
    if (inputParams) {
        if (inputParams->useFilter) {
            u32 key1 = syscall_id;
            u8 *dummy = (u8*)sysfilter.lookup(&key1);
            if (!dummy) {
                //skip if not get filter
                return 0;
            }
        }
        if(inputParams->is32) {
            bpf_probe_read_kernel(&data.lr, sizeof(data.lr), &regs->regs[14]);
        }
        else {
            bpf_probe_read_kernel(&data.lr, sizeof(data.lr), &regs->regs[30]);
        }

        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid;
        data.syscallId = syscall_id;
        data.tgid = pid_tgid >> 32;
        u32 key = syscall_id;
        struct sysdesc_t *desc = sysdesc.lookup(&key);
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            bpf_probe_read_kernel(&data.args[i], sizeof(u64), &regs->regs[i]);
            if (desc) {
                u32 pmask = 1 << i;
                u32 mask = desc->stringMask;
                //由于字符串参数不知道多长，ebpf栈只有512字节，所以只能分组发送
                if (mask & pmask) {
                    data.strBuf[0] = 0;
                    data.type = 2;
                    bpf_probe_read_str(data.strBuf, sizeof(data.strBuf), (void*)data.args[i]);
                    //bpf_trace_printk("btrace: %d %d call", data.pid, data.syscallId);
                    syscall_events.perf_submit(ctx, &data, sizeof(data));
                }
            }
        }
        bpf_probe_read_kernel(&data.pc, sizeof(data.pc), &PT_REGS_IP(regs));
        data.type = 1;
        syscall_events.perf_submit(ctx, &data, sizeof(data));
    }
    else {
        bpf_trace_printk("btrace: input is not set!!!");
    }
    return 0;
}

RAW_TRACEPOINT_PROBE(sys_exit){
    u32 tid = bpf_get_current_pid_tgid();

    PROCESS_FILTER

    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    u64 ret = ctx->args[1];

    u32 key = 0;
    struct input_data_t *inputParams = input.lookup(&key);
    if (inputParams) {
        struct syscall_data_t data = {0};

        struct entry_t *entry = entryinfo.lookup(&tid);
        if(entry){
            data.start_ns = entry->start_ns;
            data.duration_ns = bpf_ktime_get_ns() - entry->start_ns;
            #ifdef USER_STACKS
            data.user_stack_id = entry->user_stack_id;
            #endif

            #ifdef KERNEL_STACKS
            data.kernel_stack_id = entry->kernel_stack_id;
            data.kernel_ip = entry->kernel_ip;
            #endif

            TIMEOUT_FILTER
        }

        if(inputParams->is32) {
            bpf_probe_read_kernel(&data.syscallId, sizeof(data.syscallId), &regs->regs[7]);
        }
        else {
            bpf_probe_read_kernel(&data.syscallId, sizeof(data.syscallId), &regs->regs[8]);
        }
        if (inputParams->useFilter) {
            u32 key1 = data.syscallId;
            u8 *dummy = (u8*)sysfilter.lookup(&key1);
            if (!dummy) {
                //skip if not get filter
                return 0;
            }
        }
        data.type = 3;
        data.ret = ret;
        data.ret2 = __s64(ret)
        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid;
        data.tgid = pid_tgid >> 32;
        syscall_events.perf_submit(ctx, &data, sizeof(data));
    }
    else {
        //impossible
        bpf_trace_printk("btrace: input is not set!!!");
    }

    //TODO get syscall id
    return 0;
}