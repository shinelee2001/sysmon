#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <stdint.h>

// 성공: 1, 실패: 0
int tdh_read_uint32(PEVENT_RECORD ev, const wchar_t* prop_name, uint32_t* out);
int tdh_read_uint64(PEVENT_RECORD ev, const wchar_t* prop_name, uint64_t* out);

// out_wcap: wchar_t 개수
// 성공: 1, 실패: 0
int tdh_read_wstring(PEVENT_RECORD ev, const wchar_t* prop_name, wchar_t* out, size_t out_wcap);

// ANSI 문자열을 wide로 변환해서 반환
int tdh_read_astring_to_wstring(PEVENT_RECORD ev, const wchar_t* prop_name, wchar_t* out, size_t out_wcap);

// 디버깅
DWORD tdh_last_error(void);
