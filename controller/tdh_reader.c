#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include "tdh_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static DWORD g_last_err = 0;
DWORD tdh_last_error(void) { return g_last_err; }

static void set_err(DWORD e) { g_last_err = e; }

// TRACE_EVENT_INFO 로드
static PTRACE_EVENT_INFO load_event_info(PEVENT_RECORD ev, ULONG* out_size)
{
    *out_size = 0;
    set_err(ERROR_SUCCESS);

    ULONG size = 0;
    ULONG status = TdhGetEventInformation(ev, 0, NULL, NULL, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        set_err(status);
        return NULL;
    }

    PTRACE_EVENT_INFO info = (PTRACE_EVENT_INFO)malloc(size);
    if (!info) {
        set_err(ERROR_OUTOFMEMORY);
        return NULL;
    }

    status = TdhGetEventInformation(ev, 0, NULL, info, &size);
    if (status != ERROR_SUCCESS) {
        free(info);
        set_err(status);
        return NULL;
    }

    *out_size = size;
    return info;
}

// property name -> index
static int find_prop_index(PTRACE_EVENT_INFO info, const wchar_t* prop_name, ULONG* out_index)
{
    if (!info || !prop_name) return 0;

    USHORT count = info->TopLevelPropertyCount;
    PEVENT_PROPERTY_INFO arr = (PEVENT_PROPERTY_INFO)((PBYTE)info + sizeof(TRACE_EVENT_INFO));

    for (USHORT i = 0; i < count; i++) {
        ULONG off = arr[i].NameOffset;
        if (!off) continue;

        const wchar_t* name = (const wchar_t*)((PBYTE)info + off);
        if (name && _wcsicmp(name, prop_name) == 0) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

// TDH Property 데이터 가져오기 (raw bytes)
static int get_property_bytes(
    PEVENT_RECORD ev,
    PTRACE_EVENT_INFO info,
    ULONG prop_index,
    PBYTE* out_buf,
    ULONG* out_len
){
    *out_buf = NULL;
    *out_len = 0;
    set_err(ERROR_SUCCESS);

    PROPERTY_DATA_DESCRIPTOR desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.PropertyName = (ULONGLONG)((PBYTE)info + ((PEVENT_PROPERTY_INFO)((PBYTE)info + sizeof(TRACE_EVENT_INFO)))[prop_index].NameOffset);
    desc.ArrayIndex = ULONG_MAX; // not array index

    ULONG size = 0;
    ULONG status = TdhGetPropertySize(ev, 0, NULL, 1, &desc, &size);
    if (status != ERROR_SUCCESS) {
        set_err(status);
        return 0;
    }

    PBYTE buf = (PBYTE)malloc(size);
    if (!buf) {
        set_err(ERROR_OUTOFMEMORY);
        return 0;
    }
    ZeroMemory(buf, size);

    status = TdhGetProperty(ev, 0, NULL, 1, &desc, size, buf);
    if (status != ERROR_SUCCESS) {
        free(buf);
        set_err(status);
        return 0;
    }

    *out_buf = buf;
    *out_len = size;
    return 1;
}

// property의 InType 확인
static int get_in_type(PTRACE_EVENT_INFO info, ULONG prop_index, USHORT* out_inType)
{
    PEVENT_PROPERTY_INFO arr = (PEVENT_PROPERTY_INFO)((PBYTE)info + sizeof(TRACE_EVENT_INFO));
    PEVENT_PROPERTY_INFO p = &arr[prop_index];

    if (p->Flags & PropertyStruct) {
        return 0; // struct는 여기서 처리 안 함
    }

    *out_inType = p->nonStructType.InType;
    return 1;
}

int tdh_read_uint32(PEVENT_RECORD ev, const wchar_t* prop_name, uint32_t* out)
{
    if (!ev || !prop_name || !out) return 0;

    ULONG info_sz = 0;
    PTRACE_EVENT_INFO info = load_event_info(ev, &info_sz);
    if (!info) return 0;

    ULONG idx = 0;
    if (!find_prop_index(info, prop_name, &idx)) {
        free(info);
        set_err(ERROR_NOT_FOUND);
        return 0;
    }

    PBYTE buf = NULL;
    ULONG len = 0;
    if (!get_property_bytes(ev, info, idx, &buf, &len)) {
        free(info);
        return 0;
    }

    if (len < sizeof(uint32_t)) {
        free(buf);
        free(info);
        set_err(ERROR_INVALID_DATA);
        return 0;
    }

    // 타입 확인(가능하면)
    USHORT inType = 0;
    if (get_in_type(info, idx, &inType)) {
        if (!(inType == TDH_INTYPE_UINT32 || inType == TDH_INTYPE_INT32)) {
            // 그래도 len>=4면 읽기는 가능, 하지만 타입 mismatch는 알려두자
            // (확장기에서 조정 가능)
        }
    }

    memcpy(out, buf, sizeof(uint32_t));
    free(buf);
    free(info);
    set_err(ERROR_SUCCESS);
    return 1;
}

int tdh_read_uint64(PEVENT_RECORD ev, const wchar_t* prop_name, uint64_t* out)
{
    if (!ev || !prop_name || !out) return 0;

    ULONG info_sz = 0;
    PTRACE_EVENT_INFO info = load_event_info(ev, &info_sz);
    if (!info) return 0;

    ULONG idx = 0;
    if (!find_prop_index(info, prop_name, &idx)) {
        free(info);
        set_err(ERROR_NOT_FOUND);
        return 0;
    }

    PBYTE buf = NULL;
    ULONG len = 0;
    if (!get_property_bytes(ev, info, idx, &buf, &len)) {
        free(info);
        return 0;
    }

    if (len < sizeof(uint64_t)) {
        free(buf);
        free(info);
        set_err(ERROR_INVALID_DATA);
        return 0;
    }

    memcpy(out, buf, sizeof(uint64_t));
    free(buf);
    free(info);
    set_err(ERROR_SUCCESS);
    return 1;
}

int tdh_read_wstring(PEVENT_RECORD ev, const wchar_t* prop_name, wchar_t* out, size_t out_wcap)
{
    if (!ev || !prop_name || !out || out_wcap == 0) return 0;
    out[0] = L'\0';

    ULONG info_sz = 0;
    PTRACE_EVENT_INFO info = load_event_info(ev, &info_sz);
    if (!info) return 0;

    ULONG idx = 0;
    if (!find_prop_index(info, prop_name, &idx)) {
        free(info);
        set_err(ERROR_NOT_FOUND);
        return 0;
    }

    // 타입 확인: UNICODESTRING 인지 먼저 확인해보자
    USHORT inType = 0;
    int hasType = get_in_type(info, idx, &inType);

    PBYTE buf = NULL;
    ULONG len = 0;
    if (!get_property_bytes(ev, info, idx, &buf, &len)) {
        free(info);
        return 0;
    }

    if (hasType && inType == TDH_INTYPE_ANSISTRING) {
        // ANSI면 변환 함수로 유도
        free(buf);
        free(info);
        set_err(ERROR_INVALID_DATATYPE);
        return 0;
    }

    // TDH는 문자열을 보통 null-terminated wide로 줌(이벤트에 따라 len이 바이트 단위)
    // len이 wchar_t의 배수 아닐 수도 있으니 안전 처리
    size_t wchar_count = len / sizeof(wchar_t);

    // 최소 1 wchar라도 없으면 실패
    if (wchar_count == 0) {
        free(buf);
        free(info);
        set_err(ERROR_INVALID_DATA);
        return 0;
    }

    const wchar_t* ws = (const wchar_t*)buf;

    // out_wcap-1만 복사 후 널 종료
    wcsncpy(out, ws, out_wcap - 1);
    out[out_wcap - 1] = L'\0';

    free(buf);
    free(info);
    set_err(ERROR_SUCCESS);
    return 1;
}

int tdh_read_astring_to_wstring(PEVENT_RECORD ev, const wchar_t* prop_name, wchar_t* out, size_t out_wcap)
{
    if (!ev || !prop_name || !out || out_wcap == 0) return 0;
    out[0] = L'\0';

    ULONG info_sz = 0;
    PTRACE_EVENT_INFO info = load_event_info(ev, &info_sz);
    if (!info) return 0;

    ULONG idx = 0;
    if (!find_prop_index(info, prop_name, &idx)) {
        free(info);
        set_err(ERROR_NOT_FOUND);
        return 0;
    }

    USHORT inType = 0;
    int hasType = get_in_type(info, idx, &inType);

    PBYTE buf = NULL;
    ULONG len = 0;
    if (!get_property_bytes(ev, info, idx, &buf, &len)) {
        free(info);
        return 0;
    }

    if (hasType && inType != TDH_INTYPE_ANSISTRING) {
        // ANSI가 아닌데 여기로 들어왔으면 mismatch
        // 그래도 변환 시도는 가능하지만 일단 실패 처리
        free(buf);
        free(info);
        set_err(ERROR_INVALID_DATATYPE);
        return 0;
    }

    // buf는 null-terminated ANSI 문자열일 가능성이 큼
    const char* s = (const char*)buf;
    // len이 바이트이지만, null-termination 보장 안 될 수 있으니 안전하게 복사
    // MultiByteToWideChar는 null을 만나면 stop하므로, 여기서는 길이 기반으로 변환
    int src_len = (int)len;
    if (src_len <= 0) {
        free(buf);
        free(info);
        set_err(ERROR_INVALID_DATA);
        return 0;
    }

    int needed = MultiByteToWideChar(CP_ACP, 0, s, src_len, NULL, 0);
    if (needed <= 0) {
        free(buf);
        free(info);
        set_err(GetLastError());
        return 0;
    }

    // out_wcap-1까지만
    int to_write = (needed < (int)out_wcap - 1) ? needed : (int)out_wcap - 1;
    int written = MultiByteToWideChar(CP_ACP, 0, s, src_len, out, to_write);
    if (written <= 0) {
        free(buf);
        free(info);
        set_err(GetLastError());
        return 0;
    }
    out[written] = L'\0';

    free(buf);
    free(info);
    set_err(ERROR_SUCCESS);
    return 1;
}
