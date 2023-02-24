
def insert_pid_filter(bpf_text, pid):
    bpf_text = "#define FILTER_PID {}\n".format(pid) + bpf_text
    pid_filter = """
    u64 pid_tgid_ = bpf_get_current_pid_tgid();
    if (pid_tgid_ >> 32 != FILTER_PID) {
        return 0;
    }
    """
    bpf_text = bpf_text.replace("PROCESS_FILTER", pid_filter)

    return bpf_text
#

def insert_tid_filter(bpf_text, tid):
    bpf_text = "#define FILTER_TID {}\n".format(tid) + bpf_text
    tid_filter = """
    u32 tid_ = bpf_get_current_pid_tgid();
    if (tid_ != FILTER_TID) {
        return 0;
    }
    """
    bpf_text = bpf_text.replace("PROCESS_FILTER", tid_filter)

    return bpf_text
#

def insert_tids_filter(bpf_text, tids):
    tid_filter = """
    u32 tid_ = bpf_get_current_pid_tgid();
    if (!tids_filter.lookup(&tid_)) {
        return 0;
    }
    """
    bpf_text = bpf_text.replace("PROCESS_FILTER", tid_filter)

    return bpf_text
#

def insert_uid_filter(bpf_text, uid):
    bpf_text = "#define FILTER_UID {}\n".format(uid) + bpf_text
    uid_filter = """
    u32 uid_ = bpf_get_current_uid_gid();
    if (uid_ != FILTER_UID) {
        return 0;
    }
    """
    bpf_text = bpf_text.replace("PROCESS_FILTER", uid_filter)

    return bpf_text
#

def insert_name_filter(bpf_text, program_name):
    compare_statement = []
    # Android seem to truncate the process name to the
    # last 15 chars of the app name.
    for index, char in enumerate(program_name[-15:]):
        compare_statement.append(
            "(proc_name[{}] != '{}')".format(index, char))

    compare_statement = " || ".join(compare_statement)

    process_name_filter = """
    char proc_name[TASK_COMM_LEN];
    bpf_get_current_comm(&proc_name, sizeof(proc_name));

    if ({}) {{
        return 0;
    }}
    """.format(compare_statement)
    bpf_text = bpf_text.replace("PROCESS_FILTER", process_name_filter)

    return bpf_text
#
