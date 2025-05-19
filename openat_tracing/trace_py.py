from bcc import BPF
import argparse
import time
from datetime import datetime

# Define command-line arguments
parser = argparse.ArgumentParser(
    description="Trace files opened by processes")
parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
parser.add_argument("-n", "--name", type=str, help="trace processes with this name only")
args = parser.parse_args()

# BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>

struct val_t {
    u64 id;
    char comm[TASK_COMM_LEN];
    const char *fname;
};

struct data_t {
    u64 id;
    u64 ts;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[256];
};

BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);

int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename, int flags)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // TID is lower part

    FILTER_PID

    // store info for later lookup
    bpf_get_current_comm(&val.comm, sizeof(val.comm));

    FILTER_COMM

    val.id = id;
    val.fname = filename;
    infotmp.update(&id, &val);

    return 0;
}

int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};

    valp = infotmp.lookup(&id);
    if (valp == 0) {
        return 0;
    }

    data.id = id;
    data.ts = bpf_ktime_get_ns();
    data.ret = PT_REGS_RC(ctx);
    
    bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)valp->fname);
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);

    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);

    return 0;
}
"""

# Add pid filter
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %d) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')

# Add process name filter
if args.name:
    bpf_text = bpf_text.replace('FILTER_COMM',
        'if (val.comm[0] == 0 || ' +
        'strcmp(val.comm, "%s") != 0) { return 0; }' % args.name)
else:
    bpf_text = bpf_text.replace('FILTER_COMM', '')

# Initialize BPF
b = BPF(text=bpf_text)

# Find the right syscall prefix based on kernel version
syscall_fnname = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall_fnname, fn_name="trace_entry")
b.attach_kretprobe(event=syscall_fnname, fn_name="trace_return")

# Process events
print("%-9s %-6s %-16s %-3s %s" % ("TIME", "PID", "COMM", "FD", "FILENAME"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    ts = datetime.fromtimestamp(event.ts / 1000000000).strftime('%H:%M:%S')
    
    if event.ret >= 0:
        ret = event.ret
    else:
        ret = -1
    
    pid = event.id >> 32
    comm = event.comm.decode('utf-8', 'replace')
    fname = event.fname.decode('utf-8', 'replace')
    
    print("%-9s %-6d %-16s %-3d %s" % (ts, pid, comm, ret, fname))

b["events"].open_perf_buffer(print_event)

# Print instructions
filter_msg = ""
if args.pid:
    filter_msg += f" for PID {args.pid}"
if args.name:
    filter_msg += f" for process '{args.name}'"

print(f"Tracing openat() calls{filter_msg}... Press Ctrl+C to stop.")

# Run until interrupted
try:
    while True:
        b.perf_buffer_poll()
        time.sleep(0.1)
except KeyboardInterrupt:
    print("Tracing stopped.")