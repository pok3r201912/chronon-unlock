#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include "asi_transaction.hpp"
#include "candidate_scan.hpp"
extern "C" DWORD WINAPI QBPrepare(void*);
extern "C" const QBPlan* QBGetPlan();

namespace {
HMODULE module = nullptr;
std::atomic_flag started = ATOMIC_FLAG_INIT;

void log(const char* message, DWORD code = 0) {
    wchar_t path[32768]{};
    DWORD n = GetModuleFileNameW(module, path, 32768);
    if (!n || n >= 32768 - 5) return;
    auto slash = std::wcsrchr(path, L'\\');
    if (!slash) return;
    wcscpy_s(slash + 1, 32768 - (slash + 1 - path), L"QuantumBreakCinematicUnlock.log");
    HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;
    char line[512]{}; SYSTEMTIME time{}; GetLocalTime(&time);
    char suffix[32]{};
    if (code) sprintf_s(suffix, " | code=%lu", code);
    int count = sprintf_s(line, "[ChrononUnlock] %04u-%02u-%02u %02u:%02u:%02u | %s%s\r\n",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, message, suffix);
    DWORD written = 0;
    if (count > 0) WriteFile(file, line, DWORD(count), &written, nullptr);
    CloseHandle(file);
}

bool copy_image(std::uintptr_t base, std::size_t size, std::uint8_t* buffer) {
    std::size_t off = 0;
    while (off < size) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<void*>(base + off), &mbi, sizeof mbi)) return false;
        auto region = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        auto end = region + mbi.RegionSize;
        if (end <= base + off) return false;
        auto chunk = static_cast<std::size_t>(end - (base + off));
        if (chunk > size - off) chunk = size - off;
        const auto prot = mbi.Protect & 0xFF;
        const bool ok = mbi.State == MEM_COMMIT
            && prot != 0 && prot != PAGE_NOACCESS && prot != PAGE_GUARD;
        if (ok) {
            SIZE_T n = 0;
            if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(base + off),
                                   buffer + off, chunk, &n) || n != chunk)
                std::memset(buffer + off, 0, chunk);
        } else {
            std::memset(buffer + off, 0, chunk);
        }
        off += chunk;
    }
    return true;
}

bool rpm_match(std::uintptr_t abs, const void* bytes, std::size_t n) {
    BYTE got[16]{}; SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(abs), got, n, &read)
        && read == n && std::memcmp(got, bytes, n) == 0;
}

bool preferred_ready(std::uintptr_t base) {
    using namespace qb_candidate;
    if (!rpm_match(base + preferred_gate_rvas[0], gate_bytes, sizeof gate_bytes)) return false;
    if (!rpm_match(base + preferred_gate_rvas[1], gate_bytes, sizeof gate_bytes)) return false;
    if (!rpm_match(base + preferred_stop_rva, stop_prefix.data(), stop_prefix.size())) return false;
    if (!rpm_match(base + preferred_curve_original_rva, callback_bytes, sizeof callback_bytes)) return false;
    if (!rpm_match(base + preferred_cleanup_rva, cleanup_bytes, sizeof cleanup_bytes)) return false;
    std::uintptr_t slot = 0; SIZE_T n = 0;
    return ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<void*>(base + preferred_curve_slot_rva), &slot, 8, &n)
        && n == 8 && slot == base + preferred_curve_original_rva;
}

bool engine_ready() {
    auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (preferred_ready(base)) return true;
    static ULONGLONG last_scan = 0;
    const auto now = GetTickCount64();
    if (now - last_scan < 1000) return false;
    last_scan = now;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS64 nt{};
    SIZE_T n = 0;
    if (!ReadProcessMemory(GetCurrentProcess(),
                           reinterpret_cast<void*>(base + dos->e_lfanew),
                           &nt, sizeof nt, &n) || n != sizeof nt)
        return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.SizeOfImage < 0x100000)
        return false;
    const auto size = static_cast<std::size_t>(nt.OptionalHeader.SizeOfImage);
    auto buffer = static_cast<std::uint8_t*>(VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!buffer) return false;
    const bool copied = copy_image(base, size, buffer);
    const bool ok = copied && qb_candidate::signatures_visible(
        reinterpret_cast<std::uintptr_t>(buffer), size);
    VirtualFree(buffer, 0, MEM_RELEASE);
    return ok;
}

DWORD WINAPI worker(void*) {
    log("No SHA-256 lock; waiting for live engine signatures.");
    auto next = reinterpret_cast<qb_asi::NextThread>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtGetNextThread"));
    if (!next) { log("ERROR: thread enumeration unavailable", GetLastError()); return 0; }
    const auto deadline = GetTickCount64() + 120000;
    while (!engine_ready()) {
        if (GetTickCount64() >= deadline) {
            log("ERROR: cinematic signatures not found (120s). This EXE layout is too different.", ERROR_TIMEOUT);
            return 0;
        }
        Sleep(100);
    }
    DWORD error = QBPrepare(nullptr);
    if (error) { log("ERROR: native preparation failed", error); return 0; }
    const auto* p = QBGetPlan();
    if (p) {
        char found[384]{};
        sprintf_s(found,
            "signatures resolved; patches at %llX %llX %llX %llX",
            static_cast<unsigned long long>(p->patches[0].address),
            static_cast<unsigned long long>(p->patches[1].address),
            static_cast<unsigned long long>(p->patches[2].address),
            static_cast<unsigned long long>(p->patches[3].address));
        log(found);
    }
    qb_asi::InstallDiagnostic diagnostic{};
    unsigned attempts = 0;
    for (unsigned attempt = 0; attempt != 100; ++attempt) {
        attempts = attempt + 1;
        error = qb_asi::install(*QBGetPlan(), next, &diagnostic);
        if (error != ERROR_BUSY) break;
        Sleep(50);
    }
    if (error) {
        char details[384]{};
        sprintf_s(details,
            "ERROR: activation failed; no patch committed; stage=%s win32=%lu ntstatus=0x%08lX thread=%lu attempts=%u",
            diagnostic.stage, diagnostic.win32_error,
            static_cast<unsigned long>(diagnostic.nt_status), diagnostic.thread_id, attempts);
        log(details, error);
    } else log("ASI plugin is active. In-engine cinematics are uncapped.");
    return error;
}
}

extern "C" __declspec(dllexport) void InitializeASI() {
    if (started.test_and_set()) return;
    log("ASI plugin loaded.");
    HMODULE pinned = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                            reinterpret_cast<LPCWSTR>(&InitializeASI), &pinned)) {
        log("ERROR: module pinning failed", GetLastError()); return;
    }
    HANDLE thread = CreateThread(nullptr, 0, worker, nullptr, 0, nullptr);
    if (thread) CloseHandle(thread);
    else log("ERROR: worker creation failed", GetLastError());
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) module = instance;
    return TRUE;
}
