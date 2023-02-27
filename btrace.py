#!/usr/bin/python
# -*- coding: utf-8 -*-

from datetime import datetime
import time
import argparse
import json
from bcc import BPF
from ctypes import *
import argparse
import utils.sys_arm32
import utils.sys_arm64
import utils.bpf_utils

class SysDesc(Structure):
    _fields_ = [
            ("stringMask", c_int32)
    ]
#
class InputDesc(Structure):
    _fields_ = [
            ("is32", c_byte),
            ("useFilter", c_byte)
    ]
#

g_sys_platform = utils.sys_arm64

g_sysStrParamMap = {}

def print_stack(event):
    user_stack = []
    stack_traces = b.get_table("stacks")

    if args.user_stack and event.user_stack_id > 0:
        user_stack = stack_traces.walk(event.user_stack_id)

    kernel_stack = []
    if args.kernel_stack and event.kernel_stack_id > 0:
        kernel_tmp = stack_traces.walk(event.kernel_stack_id)

        # fix kernel stack
        for addr in kernel_tmp:
            kernel_stack.append(addr)

    do_delimiter = user_stack and kernel_stack

    if args.folded:
        # print folded stack output
        user_stack = list(user_stack)
        kernel_stack = list(kernel_stack)
        line = [event.comm.decode('utf-8', 'replace')] + \
            [b.sym(addr, event.tgid_pid) for addr in reversed(user_stack)] + \
            (do_delimiter and ["-"] or []) + \
            [b.ksym(addr) for addr in reversed(kernel_stack)]
        print("%s %d" % (";".join(line), 1))
    else:
        # print default multi-line stack output.
        for addr in kernel_stack:
            print("    %s" % b.ksym(addr))
        for addr in user_stack:
            print("    %s" % b.sym(addr, event.tgid_pid))

def handle(event, syscallName, debug_str):
    #if event.type == 3:
    #    print_stack(event)

    print(debug_str)
    
def print_syscall_event(cpu, data, size):
    event = b["syscall_events"].event(data)
    tm = datetime.now().strftime('%m-%d %H:%M:%S.%f')[:-3]
    outStr = ""
    syscallName = ""
    if (event.type == 1):
        systbl = g_sys_platform.g_systbl
        if (event.syscallId in systbl):
            sysUserDesc = systbl[event.syscallId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            #
            syscallName = sysUserDesc[1]
            nArgs = sysUserDesc[0]
            outStr = "%s %d-%d %s(%d) (0x%08x) (0x%08x)" % (tm, event.tgid, event.pid, syscallName, event.syscallId, event.pc, event.lr)
            listId = 0
            for i in range(0, nArgs):
                mask = 1 << i
                if (mask & sysMask):
                    assert (event.pid, event.syscallId) in g_sysStrParamMap, "(%d, %d) not in g_sysStrParamMap"%(event.pid, event.syscallId)
                    paramList = g_sysStrParamMap[(event.pid, event.syscallId)]
                    valStr = paramList[listId]
                    listId += 1
                    outStr += " [%s]"%valStr
                #
                else:
                    outStr += " [0x%08x]" % event.args[i]
                #
            #
            if ((event.pid, event.syscallId) in g_sysStrParamMap):
                g_sysStrParamMap.pop((event.pid, event.syscallId))
            #
        #
        else:
            outStr = "%s %d-%d *unknown*(%d) (0x%08x) (0x%08x) [0x%08x] [0x%08x] [0x%08x] [0x%08x] [0x%08x] [0x%08x]"%(tm, event.tgid, event.pid, event.syscallId, event.pc, event.lr, event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5])        
        #
    elif (event.type == 2):
        #收集字符串参数
        #print("------------%d %d"%(event.pid, event.syscallId))
        val = None
        if (event.pid, event.syscallId) in g_sysStrParamMap:
            val = g_sysStrParamMap[(event.pid, event.syscallId)]
        else:
            val = []
            g_sysStrParamMap[(event.pid, event.syscallId)] = val
        #
        val.append(event.strBuf)
        #print("2 pid %d %r"%(event.pid, event.strBuf))
    #
    elif(event.type == 3):        
        systbl = g_sys_platform.g_systbl
        if (event.syscallId in systbl):
            sysUserDesc = systbl[event.syscallId]
            syscallName = sysUserDesc[1]
            outStr = "%s %d-%d %s(%d) return [0x%08x]"%(tm, event.tgid, event.pid, syscallName, event.syscallId, event.ret)
        #
        else:
            outStr = "%s %d-%d *unknown*(%d) return [0x%08x]"%(tm, event.tgid, event.pid, event.syscallId, event.ret)
    #
    handle(event, syscallName, outStr)
#

def filter_name_to_id(name, syscall_tbl):
    for sysId in syscall_tbl:
        sysUserDesc = syscall_tbl[sysId]
        syscallName = sysUserDesc[1]
        if (name == syscallName):
            return sysId
        #
    #
    return -1
#

def read_filter_file(filter_path, syscall_tbl):
    r = []
    with open(filter_path, "r") as f:
        for line in f:
            line = line.strip()
            if (line == ""):
                continue
            #
            syscallId = filter_name_to_id(line, syscall_tbl)
            if (syscallId > -1):
                r.append(syscallId)
            #
        #
    #
    return r
#

def get_filter_list_from_str(filter_str, syscall_tbl):
    r = []
    l = filter_str.split(",")
    for filter_name in l:
        syscallId = filter_name_to_id(filter_name, syscall_tbl)
        if (syscallId > -1):
            r.append(syscallId)
        #
    #
    return r
#


#raw_tracepoint work since kernel 4.17
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="trace syscall.")

    program_filter = parser.add_mutually_exclusive_group(required=True)
    program_filter.add_argument("-p", "--pid", help="use process id filter", type=int)
    program_filter.add_argument("-t", "--tid", help="use thread id filter", type=str)
    program_filter.add_argument("-u", "--uid", help="use user id filter", type=int)
    program_filter.add_argument("-n", "--name", help="use process name filter", type=str)
    parser.add_argument("-to", "--timeout", help="filter function only function timedouted, used ms", type=int)
    parser.add_argument("-fd", "--folded", action="store_true", help="output folded format, one line per stack (for flame graphs)")

    program_platform = parser.add_mutually_exclusive_group(required=True)

    program_platform.add_argument("-m32", help="the target process is 32bit", action="store_true")
    program_platform.add_argument("-m64", help="the target process is 64bit", action="store_true")

    syscall_filter = parser.add_mutually_exclusive_group(required=False)
    syscall_filter.add_argument("-fp", "--filter-path", help="syscall filter file", type=str)
    syscall_filter.add_argument("-f", "--filter", help="syscall filter, example:openat,faccessat,...", type=str)

    args = parser.parse_args()
    c_file = "bpfc/btrace.c"
    with open(c_file, "r") as f:
        c_src = f.read()
        if args.pid:
            c_src = utils.bpf_utils.insert_pid_filter(c_src, args.pid)
        elif args.tid:
            c_src = utils.bpf_utils.insert_tids_filter(c_src, args.tid)
        elif args.uid:
            c_src = utils.bpf_utils.insert_uid_filter(c_src, args.uid)
        else:
            c_src = utils.bpf_utils.insert_name_filter(c_src, args.name)
        #
        timeout = 0
        if args.timeout:
            timeout = args.timeout
        c_src = utils.bpf_utils.insert_timeout_filter(c_src, timeout)
        #
        b = BPF(text=c_src)
        input_map = b["input"]
        isM32 = 0
        if(args.m32):
            isM32 = 1
            g_sys_platform = utils.sys_arm32
        #
        else:
            isM32 = 0
            g_sys_platform = utils.sys_arm64
        #
        useFilter = 0
        filters = []
        if (args.filter_path):
            filters = read_filter_file(args.filter_path, g_sys_platform.g_systbl)
        #
        elif(args.filter):
            filters = get_filter_list_from_str(args.filter, g_sys_platform.g_systbl)
        #
        if (len(filters) > 0):
            useFilter = 1
            tblfilter = b["sysfilter"]
            for filter_sysId in filters:
                tblfilter[c_int(filter_sysId)] = c_byte(1)
            #
        #
        if args.tid:
            tids = args.tid.split(',')
            tid_b = b["tids_filter"]
            for tid in tids:
                tid_b[c_int(int(tid))] = c_int(int(tid))
        #
        inputVal = InputDesc(c_byte(isM32), c_byte(useFilter))
        input_map[c_int(0)] = inputVal
        systbl = g_sys_platform.g_systbl
        tbl = b["sysdesc"]
        for sysId in systbl:
            sysUserDesc = systbl[sysId]
            sysMask = 0
            n = len(sysUserDesc)
            if (n > 2):
                sysMask = sysUserDesc[2]
            sysval = SysDesc(c_int32(sysMask))
            tbl[c_int(sysId)] = sysval
        #

        print("monitoring...")
        #page_cnt必须设置大一点，否则会丢包
        b["syscall_events"].open_perf_buffer(print_syscall_event, page_cnt=4096)

        while True:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit()
            #
        #
        #b.trace_print()
    #
#