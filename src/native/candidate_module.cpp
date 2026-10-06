#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <atomic>
#include <new>
#include "candidate_engine_adapter.hpp"
#include "candidate_hook_plan.hpp"
#include "candidate_module_api.hpp"
#include "candidate_scan.hpp"

namespace {
using namespace qb_candidate;
QBPlan plan{};
Resolved resolved{};
RUNTIME_FUNCTION runtime_entry{};
std::atomic<bool> ready{false};
std::atomic_flag preparing = ATOMIC_FLAG_INIT;
alignas(Adapter) std::byte adapter_storage[sizeof(Adapter)];
Adapter* adapter = nullptr;

int target_type(void* target) {
    auto vtable = field<std::uintptr_t>(target, 0);
    auto fn = field<int(*)(void*)>(reinterpret_cast<void*>(vtable), 0x190);
    return fn(target);
}
void curve_hook(void* event, int pass, float frame) {
    adapter->interpolate(event, pass, frame);
}
void stop_hook(void* timeline) { adapter->stop(timeline); }

void* allocate_near(std::uintptr_t target) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const auto step = static_cast<std::uintptr_t>(info.dwAllocationGranularity);
    const auto center = target & ~(step - 1);
    for (std::uintptr_t delta = step; delta < 0x7FFF0000; delta += step) {
        if (center > delta) {
            if (auto p = VirtualAlloc(reinterpret_cast<void*>(center - delta),
                4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) return p;
        }
        if (auto p = VirtualAlloc(reinterpret_cast<void*>(center + delta),
            4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) return p;
    }
    return nullptr;
}

DWORD prepare(std::uintptr_t image) {
    if (ready.load(std::memory_order_acquire))
        return plan.image == image ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS;
    if (preparing.test_and_set()) return ERROR_BUSY;
    struct Unlock { ~Unlock() { preparing.clear(); } } unlock;
    if (ready.load(std::memory_order_acquire))
        return plan.image == image ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0
        || dos->e_lfanew > 0x1000) return ERROR_BAD_EXE_FORMAT;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE
        || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || nt->OptionalHeader.SizeOfImage < 0x100000
        || nt->OptionalHeader.SizeOfImage > 0x4000000) return ERROR_BAD_EXE_FORMAT;
    const auto size = static_cast<std::size_t>(nt->OptionalHeader.SizeOfImage);
    if (!resolve(image, size, resolved)) return ERROR_REVISION_MISMATCH;
    auto memory = static_cast<std::uint8_t*>(allocate_near(image + resolved.stop_rva));
    if (!memory) return ERROR_NOT_ENOUGH_MEMORY;
    auto hook = make_hook_plan(image, reinterpret_cast<std::uintptr_t>(memory),
                              reinterpret_cast<std::uintptr_t>(&stop_hook),
                              resolved.stop_rva);
    std::memcpy(memory, hook.executable.data(), hook.executable.size());
    DWORD old = 0;
    if (!VirtualProtect(memory, 4096, PAGE_EXECUTE_READ, &old)
        || !FlushInstructionCache(GetCurrentProcess(), memory, 4096)) {
        auto error = GetLastError(); VirtualFree(memory, 0, MEM_RELEASE); return error;
    }
    runtime_entry = {hook.function_begin, hook.function_end, hook.unwind_info};
    if (!RtlAddFunctionTable(&runtime_entry, 1, reinterpret_cast<DWORD64>(memory))) {
        VirtualFree(memory, 0, MEM_RELEASE); return ERROR_INVALID_FUNCTION;
    }
    const auto timeline_vt = resolved.timeline_vtable_rva ? image + resolved.timeline_vtable_rva : 0;
    const auto curve_vt = resolved.curve_vtable_rva ? image + resolved.curve_vtable_rva : 0;
    adapter = new (adapter_storage) Adapter({timeline_vt, curve_vt,
        reinterpret_cast<void(*)(void*, int, float)>(image + resolved.curve_original_rva),
        reinterpret_cast<void(*)(void*)>(image + resolved.cleanup_rva),
        reinterpret_cast<void(*)(void*)>(memory + 32), target_type});
    plan.version = 1; plan.count = 4; plan.image = image;
    plan.relay = reinterpret_cast<std::uint64_t>(memory);
    auto add = [&](int i, std::uint32_t rva, const void* replacement, std::uint32_t n) {
        auto& p = plan.patches[i]; p.address = image + rva; p.length = n;
        std::memcpy(p.original, reinterpret_cast<void*>(p.address), n);
        std::memcpy(p.replacement, replacement, n);
    };
    const auto curve = reinterpret_cast<std::uintptr_t>(&curve_hook);
    add(0, resolved.curve_slot_rva, &curve, 8);
    add(1, resolved.stop_rva, hook.stop_replacement.data(), 11);
    const std::uint8_t jump = 0xEB;
    add(2, resolved.cap_branch_rvas[0], &jump, 1);
    add(3, resolved.cap_branch_rvas[1], &jump, 1);
    ready.store(true, std::memory_order_release);
    return ERROR_SUCCESS;
}
}

extern "C" __declspec(dllexport) DWORD WINAPI QBPrepare(void*) {
    return prepare(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)));
}
extern "C" __declspec(dllexport) const QBPlan* QBGetPlan() {
    return ready.load(std::memory_order_acquire) ? &plan : nullptr;
}
extern "C" __declspec(dllexport) DWORD WINAPI QBCopyPlan(void* destination) {
    if (!destination) return ERROR_INVALID_PARAMETER;
    if (!ready.load(std::memory_order_acquire)) return ERROR_NOT_READY;
    std::memcpy(destination, &plan, sizeof plan);
    return ERROR_SUCCESS;
}
#ifdef QB_MODULE_TEST
extern "C" __declspec(dllexport) DWORD QBPrepareTest(std::uintptr_t image) { return prepare(image); }
#elif !defined(QB_ASI)
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
#endif
