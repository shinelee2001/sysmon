#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "etw_consumer.h"

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "tdh_reader.h"
#include "jsonl_writer.h"
#include "guid.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")

// ============================================================
// Stop flag (Ctrl+C handler can call etw_consumer_request_stop)
// ============================================================
static volatile LONG g_stop = 0;
void etw_consumer_request_stop(void) { InterlockedExchange(&g_stop, 1); }

// ============================================================
// Hostname cache
// ============================================================
static wchar_t g_host[256] = L"";
static void ensure_host_cached(void)
{
    if (g_host[0]) return;
    DWORD sz = (DWORD)(sizeof(g_host) / sizeof(g_host[0]));
    if (!GetComputerNameW(g_host, &sz)) {
        wcscpy_s(g_host, 256, L"UNKNOWN");
    }
}

// ============================================================
// Time helper (wall clock ISO8601 UTC)
// ============================================================
static void iso8601_utc_now(char out[64], uint64_t* out_filetime100ns)
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;

    if (out_filetime100ns) *out_filetime100ns = (uint64_t)u.QuadPart;

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    _snprintf(out, 64, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

// ============================================================
// PID -> process_guid map (simple open addressing hash table)
// - good enough for "minimal collector" stage
// ============================================================
typedef struct PID_GUID_ENTRY {
    uint32_t pid;
    uint64_t start_ts_100ns;
    char guid[64];
    uint8_t used;
} PID_GUID_ENTRY;

static PID_GUID_ENTRY* g_map = NULL;
static size_t g_map_cap = 0;
static size_t g_map_size = 0;

static uint64_t hash_u32(uint32_t x)
{
    uint64_t h = x;
    h ^= h >> 16;
    h *= 0x7feb352dULL;
    h ^= h >> 15;
    h *= 0x846ca68bULL;
    h ^= h >> 16;
    return h;
}

static int map_init(size_t cap_pow2)
{
    g_map_cap = cap_pow2;
    g_map_size = 0;
    g_map = (PID_GUID_ENTRY*)calloc(g_map_cap, sizeof(PID_GUID_ENTRY));
    return g_map != NULL;
}

static void map_free(void)
{
    free(g_map);
    g_map = NULL;
    g_map_cap = 0;
    g_map_size = 0;
}

static void map_grow_if_needed(void);

static void map_put(uint32_t pid, uint64_t start_ts_100ns, const char* guid)
{
    map_grow_if_needed();

    uint64_t h = hash_u32(pid);
    size_t idx = (size_t)(h & (g_map_cap - 1));

    for (size_t probe = 0; probe < g_map_cap; probe++) {
        PID_GUID_ENTRY* e = &g_map[idx];
        if (!e->used || e->pid == pid) {
            e->used = 1;
            e->pid = pid;
            e->start_ts_100ns = start_ts_100ns;
            strncpy_s(e->guid, sizeof(e->guid), guid ? guid : "", _TRUNCATE);
            if (probe == 0 && !e->used) g_map_size++;
            return;
        }
        idx = (idx + 1) & (g_map_cap - 1);
    }
}

static int map_get(uint32_t pid, char out_guid[64])
{
    if (!g_map || g_map_cap == 0) return 0;

    uint64_t h = hash_u32(pid);
    size_t idx = (size_t)(h & (g_map_cap - 1));

    for (size_t probe = 0; probe < g_map_cap; probe++) {
        PID_GUID_ENTRY* e = &g_map[idx];
        if (!e->used) return 0;
        if (e->pid == pid) {
            strncpy_s(out_guid, 64, e->guid, _TRUNCATE);
            return 1;
        }
        idx = (idx + 1) & (g_map_cap - 1);
    }
    return 0;
}

static void map_del(uint32_t pid)
{
    if (!g_map || g_map_cap == 0) return;

    uint64_t h = hash_u32(pid);
    size_t idx = (size_t)(h & (g_map_cap - 1));

    for (size_t probe = 0; probe < g_map_cap; probe++) {
        PID_GUID_ENTRY* e = &g_map[idx];
        if (!e->used) return;
        if (e->pid == pid) {
            // tombstone: mark as unused and reinsert following cluster (simple but safe)
            e->used = 0;
            e->pid = 0;
            e->start_ts_100ns = 0;
            e->guid[0] = '\0';
            // Rehash cluster
            size_t j = (idx + 1) & (g_map_cap - 1);
            while (g_map[j].used) {
                PID_GUID_ENTRY tmp = g_map[j];
                g_map[j].used = 0;
                map_put(tmp.pid, tmp.start_ts_100ns, tmp.guid);
                j = (j + 1) & (g_map_cap - 1);
            }
            return;
        }
        idx = (idx + 1) & (g_map_cap - 1);
    }
}

static void map_grow_if_needed(void)
{
    if (!g_map) return;
    // load factor ~ 0.6
    if ((g_map_size + 1) * 10 < g_map_cap * 6) return;

    size_t new_cap = g_map_cap * 2;
    PID_GUID_ENTRY* old = g_map;
    size_t old_cap = g_map_cap;

    g_map = (PID_GUID_ENTRY*)calloc(new_cap, sizeof(PID_GUID_ENTRY));
    if (!g_map) {
        // if grow fails, keep old (best effort)
        g_map = old;
        return;
    }

    g_map_cap = new_cap;
    g_map_size = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].used) {
            map_put(old[i].pid, old[i].start_ts_100ns, old[i].guid);
            g_map_size++;
        }
    }
    free(old);
}

// ============================================================
// TDH helpers to get Task/Opcode "names" for routing
// ============================================================
static int tdh_get_task_opcode_names(PEVENT_RECORD ev, wchar_t* taskBuf, size_t taskCap,
                                    wchar_t* opcodeBuf, size_t opcodeCap)
{
    if (taskBuf && taskCap) taskBuf[0] = L'\0';
    if (opcodeBuf && opcodeCap) opcodeBuf[0] = L'\0';

    ULONG size = 0;
    ULONG status = TdhGetEventInformation(ev, 0, NULL, NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER) return 0;

    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(size);
    if (!info) return 0;

    status = TdhGetEventInformation(ev, 0, NULL, info, &size);
    if (status != ERROR_SUCCESS) {
        free(info);
        return 0;
    }

    if (taskBuf && taskCap && info->TaskNameOffset) {
        const wchar_t* tn = (const wchar_t*)((PBYTE)info + info->TaskNameOffset);
        wcsncpy_s(taskBuf, taskCap, tn, _TRUNCATE);
    }
    if (opcodeBuf && opcodeCap && info->OpcodeNameOffset) {
        const wchar_t* on = (const wchar_t*)((PBYTE)info + info->OpcodeNameOffset);
        wcsncpy_s(opcodeBuf, opcodeCap, on, _TRUNCATE);
    }

    free(info);
    return 1;
}

static int wstr_eqi(const wchar_t* a, const wchar_t* b)
{
    if (!a || !b) return 0;
    return _wcsicmp(a, b) == 0;
}

// ============================================================
// network address extraction (best-effort)
// - tries multiple property names
// - supports IPv4 packed (uint32) and IPv6 (16 bytes) if TDH returns bytes
// ============================================================
static void ipv4_from_u32(uint32_t v, char out[64])
{
    // Kernel often uses network byte order. We'll try both.
    uint8_t b1 = (uint8_t)((v >> 24) & 0xFF);
    uint8_t b2 = (uint8_t)((v >> 16) & 0xFF);
    uint8_t b3 = (uint8_t)((v >> 8) & 0xFF);
    uint8_t b4 = (uint8_t)(v & 0xFF);

    // If it looks like 0.0.0.0 in this order, try reverse
    _snprintf(out, 64, "%u.%u.%u.%u", b1, b2, b3, b4);
    if (b1 == 0 && b2 == 0 && b3 == 0 && b4 == 0) {
        uint8_t r1 = (uint8_t)(v & 0xFF);
        uint8_t r2 = (uint8_t)((v >> 8) & 0xFF);
        uint8_t r3 = (uint8_t)((v >> 16) & 0xFF);
        uint8_t r4 = (uint8_t)((v >> 24) & 0xFF);
        _snprintf(out, 64, "%u.%u.%u.%u", r1, r2, r3, r4);
    }
}

static int try_read_u32_any(PEVENT_RECORD ev, const wchar_t** names, size_t n, uint32_t* out)
{
    for (size_t i = 0; i < n; i++) {
        if (tdh_read_uint32(ev, names[i], out)) return 1;
    }
    return 0;
}

static int read_process_id_best_effort(PEVENT_RECORD ev, uint32_t* pid_out)
{
    const wchar_t* names[] = { L"ProcessId", L"PID", L"Pid", L"processId" };
    return try_read_u32_any(ev, names, sizeof(names)/sizeof(names[0]), pid_out);
}

static int read_parent_id_best_effort(PEVENT_RECORD ev, uint32_t* ppid_out)
{
    const wchar_t* names[] = { L"ParentId", L"ParentProcessId", L"PPID", L"ParentPid" };
    return try_read_u32_any(ev, names, sizeof(names)/sizeof(names[0]), ppid_out);
}

static void read_image_cmd_best_effort(PEVENT_RECORD ev, wchar_t* image, size_t imageCap,
                                      wchar_t* cmd, size_t cmdCap)
{
    if (image && imageCap) image[0] = L'\0';
    if (cmd && cmdCap) cmd[0] = L'\0';

    // Common kernel-ish property names (best-effort)
    const wchar_t* imgNames[] = { L"ImageFileName", L"ImageName", L"ProcessName", L"FileName" };
    for (size_t i = 0; i < sizeof(imgNames)/sizeof(imgNames[0]); i++) {
        if (tdh_read_wstring(ev, imgNames[i], image, imageCap)) break;
    }

    const wchar_t* cmdNames[] = { L"CommandLine", L"CmdLine", L"ProcessCommandLine" };
    for (size_t i = 0; i < sizeof(cmdNames)/sizeof(cmdNames[0]); i++) {
        if (tdh_read_wstring(ev, cmdNames[i], cmd, cmdCap)) break;
    }
}

static void read_tcp_tuple_best_effort(
    PEVENT_RECORD ev,
    char src_ip[64], uint16_t* src_port,
    char dst_ip[64], uint16_t* dst_port
){
    strcpy_s(src_ip, 64, "");
    strcpy_s(dst_ip, 64, "");
    *src_port = 0;
    *dst_port = 0;

    // Ports
    uint32_t sp = 0, dp = 0;
    const wchar_t* spNames[] = { L"SourcePort", L"sport", L"SrcPort", L"src_port" };
    const wchar_t* dpNames[] = { L"DestPort", L"DestinationPort", L"dport", L"DstPort", L"dst_port" };
    if (try_read_u32_any(ev, spNames, sizeof(spNames)/sizeof(spNames[0]), &sp)) *src_port = (uint16_t)sp;
    if (try_read_u32_any(ev, dpNames, sizeof(dpNames)/sizeof(dpNames[0]), &dp)) *dst_port = (uint16_t)dp;

    // IPv4 addresses often appear as uint32
    uint32_t sa = 0, da = 0;
    const wchar_t* saNames[] = { L"SourceAddress", L"saddr", L"SrcAddr", L"src_ip", L"Saddr" };
    const wchar_t* daNames[] = { L"DestAddress", L"DestinationAddress", L"daddr", L"DstAddr", L"dst_ip", L"Daddr" };

    if (try_read_u32_any(ev, saNames, sizeof(saNames)/sizeof(saNames[0]), &sa)) {
        ipv4_from_u32(sa, src_ip);
    }
    if (try_read_u32_any(ev, daNames, sizeof(daNames)/sizeof(daNames[0]), &da)) {
        ipv4_from_u32(da, dst_ip);
    }
}

// ============================================================
// Event routing + JSONL emission
// ============================================================
static VOID WINAPI on_event(PEVENT_RECORD ev)
{
    if (InterlockedCompareExchange(&g_stop, 0, 0) != 0) return;

    ensure_host_cached();

    // Determine task/opcode names (best-effort)
    wchar_t task[128], opcode[128];
    task[0] = L'\0'; opcode[0] = L'\0';
    tdh_get_task_opcode_names(ev, task, 128, opcode, 128);

    char ts[64];
    uint64_t now100ns = 0;
    iso8601_utc_now(ts, &now100ns);

    // ---- PROCESS START / END ----
    // Common TDH names for kernel process events typically show task "Process"
    if (wstr_eqi(task, L"Process")) {
        // START
        if (wstr_eqi(opcode, L"Start") || wstr_eqi(opcode, L"Start/Thread") || wstr_eqi(opcode, L"Start Process")) {
            uint32_t pid = 0, ppid = 0;
            read_process_id_best_effort(ev, &pid);
            read_parent_id_best_effort(ev, &ppid);

            wchar_t image[1024], cmdline[2048];
            read_image_cmd_best_effort(ev, image, 1024, cmdline, 2048);

            char pguid[64];
            make_process_guid(pid, now100ns, image, pguid);

            // update pid->guid map
            map_put(pid, now100ns, pguid);

            jsonl_write_proc_start(
                ts, pid, ppid,
                image,
                cmdline,
                pguid,
                g_host
            );
            return;
        }

        // END
        if (wstr_eqi(opcode, L"End") || wstr_eqi(opcode, L"Stop") || wstr_eqi(opcode, L"End Process")) {
            uint32_t pid = 0;
            read_process_id_best_effort(ev, &pid);

            char pguid[64] = "";
            if (!map_get(pid, pguid)) {
                // best-effort: if we never saw start, still emit with empty guid
                strcpy_s(pguid, 64, "");
            } else {
                // remove mapping now (PID reuse 대비)
                map_del(pid);
            }

            jsonl_write_proc_end(ts, pid, pguid);
            return;
        }
    }

    // ---- TCP CONNECT ----
    // Task name might be "TcpIp" or "TCPIP" depending on metadata.
    if (wstr_eqi(task, L"TcpIp") || wstr_eqi(task, L"TCPIP") || wstr_eqi(task, L"Tcpip")) {
        // opcode might be "Connect" or "ConnectIPV4"/"ConnectIPV6"
        if (wstr_eqi(opcode, L"Connect") || wstr_eqi(opcode, L"ConnectIPV4") || wstr_eqi(opcode, L"ConnectIPV6")) {
            uint32_t pid = 0;
            read_process_id_best_effort(ev, &pid);

            char pguid[64] = "";
            map_get(pid, pguid); // may be empty if unknown

            char src_ip[64], dst_ip[64];
            uint16_t src_port = 0, dst_port = 0;
            read_tcp_tuple_best_effort(ev, src_ip, &src_port, dst_ip, &dst_port);

            // If tuple is missing, still allow emission (schema 확장은 나중)
            jsonl_write_net_connect(ts, pid, pguid, src_ip, src_port, dst_ip, dst_port);
            return;
        }
    }

    // other events ignored (minimal spec)
}

// ============================================================
// ETW consumption loop
// ============================================================
int etw_consume(const wchar_t* session_name)
{
    if (!session_name) return 0;

    ensure_host_cached();

    if (!map_init(2048)) {
        fprintf(stderr, "pid->guid map init failed\n");
        return 0;
    }

    EVENT_TRACE_LOGFILEW log;
    ZeroMemory(&log, sizeof(log));

    log.LoggerName = (LPWSTR)session_name;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = (PEVENT_RECORD_CALLBACK)on_event;

    TRACEHANDLE h = OpenTraceW(&log);
    if (h == INVALID_PROCESSTRACE_HANDLE) {
        DWORD e = GetLastError();
        fprintf(stderr, "OpenTrace failed: %lu\n", e);
        map_free();
        return 0;
    }

    ULONG status = ProcessTrace(&h, 1, NULL, NULL);

    CloseTrace(h);
    map_free();

    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        fprintf(stderr, "ProcessTrace returned: %lu\n", status);
        return 0;
    }
    return 1;
}
