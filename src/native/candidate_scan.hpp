// Locate cinematic-unlock sites by preferred RVAs, then by byte signatures.
// No SHA-256 lock. Works on Steam, Steamless-unpacked, and close rebuilds
// that still contain the same Northlight instruction sequences.
#pragma once
#include "candidate_hook_plan.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace qb_candidate {
inline constexpr std::uint8_t gate_bytes[]{0x80, 0xB9, 0x74, 0x07, 0, 0, 0, 0x74, 0x11};
inline constexpr std::uint8_t callback_bytes[]{0x83, 0xFA, 0x02, 0x75, 0x5B};
inline constexpr std::uint8_t cleanup_bytes[]{0x40, 0x53, 0x48, 0x83, 0xEC, 0x30, 0x83, 0x79, 0x38, 0x02};
inline constexpr std::uint32_t preferred_stop_rva = 0x2DBE40;
inline constexpr std::uint32_t preferred_curve_slot_rva = 0xAB9158;
inline constexpr std::uint32_t preferred_curve_original_rva = 0x147930;
inline constexpr std::uint32_t preferred_cleanup_rva = 0x147810;
inline constexpr std::array<std::uint32_t, 2> preferred_cap_branch_rvas{0x2DACB8, 0x2DBCC6};
inline constexpr std::uint32_t preferred_gate_rvas[2]{0x2DACB1, 0x2DBCBF};
inline constexpr std::uint32_t preferred_timeline_vtable_rva = 0xB044A8;
inline constexpr std::uint32_t preferred_curve_vtable_rva = 0xAB90D8;
inline constexpr std::uint32_t curve_vtable_to_slot = 0x80;

struct Resolved {
    std::uint32_t cap_branch_rvas[2]{};
    std::uint32_t stop_rva = 0;
    std::uint32_t curve_slot_rva = 0;
    std::uint32_t curve_original_rva = 0;
    std::uint32_t cleanup_rva = 0;
    std::uint32_t timeline_vtable_rva = 0;
    std::uint32_t curve_vtable_rva = 0;
};

inline bool bytes_at(std::uintptr_t image, std::size_t size, std::uint32_t rva,
                     const void* bytes, std::size_t n) noexcept {
    if (!n || static_cast<std::uint64_t>(rva) + n > size) return false;
    return std::memcmp(reinterpret_cast<const void*>(image + rva), bytes, n) == 0;
}

inline unsigned collect(std::uintptr_t image, std::size_t size, const std::uint8_t* pat,
                        std::size_t n, std::uint32_t* out, unsigned cap) noexcept {
    unsigned count = 0;
    if (!n || size < n || !out || !cap) return 0;
    for (std::size_t i = 0; i + n <= size && count < cap; ++i) {
        if (std::memcmp(reinterpret_cast<const void*>(image + i), pat, n) == 0)
            out[count++] = static_cast<std::uint32_t>(i);
    }
    return count;
}

inline bool try_preferred(std::uintptr_t image, std::size_t size, Resolved& out) noexcept {
    if (!bytes_at(image, size, preferred_gate_rvas[0], gate_bytes, sizeof gate_bytes)
        || !bytes_at(image, size, preferred_gate_rvas[1], gate_bytes, sizeof gate_bytes)
        || !bytes_at(image, size, preferred_stop_rva, stop_prefix.data(), stop_prefix.size())
        || !bytes_at(image, size, preferred_curve_original_rva, callback_bytes, sizeof callback_bytes)
        || !bytes_at(image, size, preferred_cleanup_rva, cleanup_bytes, sizeof cleanup_bytes))
        return false;
    if (static_cast<std::uint64_t>(preferred_curve_slot_rva) + 8 > size) return false;
    std::uintptr_t slot = 0;
    std::memcpy(&slot, reinterpret_cast<const void*>(image + preferred_curve_slot_rva), 8);
    if (slot != image + preferred_curve_original_rva) return false;
    out.cap_branch_rvas[0] = preferred_cap_branch_rvas[0];
    out.cap_branch_rvas[1] = preferred_cap_branch_rvas[1];
    out.stop_rva = preferred_stop_rva;
    out.curve_slot_rva = preferred_curve_slot_rva;
    out.curve_original_rva = preferred_curve_original_rva;
    out.cleanup_rva = preferred_cleanup_rva;
    out.timeline_vtable_rva = preferred_timeline_vtable_rva;
    out.curve_vtable_rva = preferred_curve_vtable_rva;
    return true;
}

inline std::uint32_t nearest_after(const std::uint32_t* hits, unsigned n, std::uint32_t origin,
                                   std::uint32_t window) noexcept {
    std::uint32_t best = 0;
    std::uint32_t best_delta = window + 1;
    for (unsigned i = 0; i < n; ++i) {
        if (hits[i] < origin) continue;
        const auto d = hits[i] - origin;
        if (d <= window && d < best_delta) {
            best_delta = d;
            best = hits[i];
        }
    }
    return best;
}

inline bool find_slot(std::uintptr_t image, std::size_t size, std::uint32_t curve_rva,
                      std::uint32_t& slot_rva) noexcept {
    if (curve_rva + 1 > size) return false;
    const auto want = image + curve_rva;
    std::uint32_t hits[8]{};
    unsigned n = 0;
    for (std::size_t i = 0; i + 8 <= size && n < 8; i += 8) {
        std::uintptr_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void*>(image + i), 8);
        if (value == want) hits[n++] = static_cast<std::uint32_t>(i);
    }
    if (!n) return false;
    for (unsigned i = 0; i < n; ++i)
        if (hits[i] == preferred_curve_slot_rva) {
            slot_rva = hits[i];
            return true;
        }
    for (unsigned i = 0; i < n; ++i)
        if (hits[i] < curve_rva || hits[i] > curve_rva + 0x40) {
            slot_rva = hits[i];
            return true;
        }
    slot_rva = hits[0];
    return true;
}

inline bool scan_buffer(std::uintptr_t image, std::size_t size, Resolved& out) noexcept {
    std::uint32_t gates[8]{};
    const auto gate_n = collect(image, size, gate_bytes, sizeof gate_bytes, gates, 8);
    if (gate_n < 2) return false;
    std::uint32_t stops[8]{};
    const auto stop_n = collect(image, size, stop_prefix.data(), stop_prefix.size(), stops, 8);
    std::uint32_t callbacks[16]{};
    const auto cb_n = collect(image, size, callback_bytes, sizeof callback_bytes, callbacks, 16);
    std::uint32_t cleanups[8]{};
    const auto cl_n = collect(image, size, cleanup_bytes, sizeof cleanup_bytes, cleanups, 8);
    if (!stop_n || !cb_n || !cl_n) return false;

    out.cap_branch_rvas[0] = gates[0] + 7;
    out.cap_branch_rvas[1] = gates[1] + 7;

    const auto later_gate = gates[1] > gates[0] ? gates[1] : gates[0];
    out.stop_rva = nearest_after(stops, stop_n, later_gate, 0x800);
    if (!out.stop_rva) out.stop_rva = stops[0];

    out.cleanup_rva = 0;
    out.curve_original_rva = 0;
    for (unsigned i = 0; i < cl_n && !out.curve_original_rva; ++i) {
        const auto cb = nearest_after(callbacks, cb_n, cleanups[i], 0x400);
        if (cb) {
            out.cleanup_rva = cleanups[i];
            out.curve_original_rva = cb;
        }
    }
    if (!out.curve_original_rva) {
        out.cleanup_rva = cleanups[0];
        out.curve_original_rva = callbacks[0];
    }
    if (!find_slot(image, size, out.curve_original_rva, out.curve_slot_rva)) return false;
    if (out.curve_slot_rva >= curve_vtable_to_slot)
        out.curve_vtable_rva = out.curve_slot_rva - curve_vtable_to_slot;
    out.timeline_vtable_rva = 0;
    return out.cap_branch_rvas[0] && out.cap_branch_rvas[1] && out.stop_rva
        && out.curve_original_rva && out.cleanup_rva && out.curve_slot_rva;
}

inline bool signatures_visible(std::uintptr_t image, std::size_t size) noexcept {
    std::uint32_t gates[2]{};
    std::uint32_t stops[1]{};
    std::uint32_t callbacks[1]{};
    std::uint32_t cleanups[1]{};
    return collect(image, size, gate_bytes, sizeof gate_bytes, gates, 2) >= 2
        && collect(image, size, stop_prefix.data(), stop_prefix.size(), stops, 1) >= 1
        && collect(image, size, callback_bytes, sizeof callback_bytes, callbacks, 1) >= 1
        && collect(image, size, cleanup_bytes, sizeof cleanup_bytes, cleanups, 1) >= 1;
}

inline bool resolve(std::uintptr_t image, std::size_t size, Resolved& out) noexcept {
    out = {};
    if (try_preferred(image, size, out)) return true;
    return scan_buffer(image, size, out);
}
}
