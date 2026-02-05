#include "jsonl_writer.h"
#include <stdio.h>

static FILE* g_fp = NULL;

int jsonl_open(const wchar_t* path)
{
    if (!path) return 0;
    if (g_fp) {
        fclose(g_fp);
        g_fp = NULL;
    }
    g_fp = _wfopen(path, L"ab");
    return g_fp != NULL;
}

void jsonl_close(void)
{
    if (g_fp) fclose(g_fp);
    g_fp = NULL;
}

void jsonl_write_proc_start(
    const char* ts,
    uint32_t pid,
    uint32_t ppid,
    const wchar_t* image,
    const wchar_t* cmdline,
    const char* process_guid,
    const wchar_t* host
){
    if (!g_fp) return;
    const char* ts_safe = ts ? ts : "";
    const wchar_t* image_safe = image ? image : L"";
    const wchar_t* cmdline_safe = cmdline ? cmdline : L"";
    const char* guid_safe = process_guid ? process_guid : "";
    const wchar_t* host_safe = host ? host : L"";

    fprintf(g_fp,
        "{\"ts\":\"%s\",\"event_type\":\"proc_start\","
        "\"pid\":%u,\"ppid\":%u,"
        "\"image\":\"%S\",\"cmdline\":\"%S\","
        "\"host\":\"%S\",\"process_guid\":\"%s\"}\n",
        ts_safe, pid, ppid, image_safe, cmdline_safe, host_safe, guid_safe
    );
    fflush(g_fp);
}

void jsonl_write_proc_end(
    const char* ts,
    uint32_t pid,
    const char* process_guid
){
    if (!g_fp) return;
    const char* ts_safe = ts ? ts : "";
    const char* guid_safe = process_guid ? process_guid : "";

    fprintf(g_fp,
        "{\"ts\":\"%s\",\"event_type\":\"proc_end\","
        "\"pid\":%u,\"process_guid\":\"%s\"}\n",
        ts_safe, pid, guid_safe
    );
    fflush(g_fp);
}

void jsonl_write_net_connect(
    const char* ts,
    uint32_t pid,
    const char* process_guid,
    const char* src_ip,
    uint16_t src_port,
    const char* dst_ip,
    uint16_t dst_port
){
    if (!g_fp) return;
    const char* ts_safe = ts ? ts : "";
    const char* guid_safe = process_guid ? process_guid : "";
    const char* src_ip_safe = src_ip ? src_ip : "";
    const char* dst_ip_safe = dst_ip ? dst_ip : "";

    fprintf(g_fp,
        "{\"ts\":\"%s\",\"event_type\":\"net_connect\","
        "\"pid\":%u,\"process_guid\":\"%s\","
        "\"src_ip\":\"%s\",\"src_port\":%u,"
        "\"dst_ip\":\"%s\",\"dst_port\":%u}\n",
        ts_safe, pid, guid_safe, src_ip_safe, src_port, dst_ip_safe, dst_port
    );
    fflush(g_fp);
}
