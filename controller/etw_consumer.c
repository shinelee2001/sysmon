// callback 내부에서
if (task == PROCESS && opcode == START) {
    // pid, ppid, image, cmdline 파싱
    // make_process_guid(...)
    // jsonl_write_proc_start(...)
}
else if (task == PROCESS && opcode == END) {
    // jsonl_write_proc_end(...)
}
else if (task == TCPIP && opcode == CONNECT) {
    // jsonl_write_net_connect(...)
}
