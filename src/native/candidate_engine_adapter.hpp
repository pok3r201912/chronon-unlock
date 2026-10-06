#pragma once
#include "candidate_dof_policy.hpp"
#include <cstddef>
#include <cstring>

namespace qb_candidate {
template<class T> T field(const void* object, std::size_t offset) noexcept {
    T value;
    std::memcpy(&value, static_cast<const std::byte*>(object) + offset, sizeof value);
    return value;
}

struct Engine {
    std::uintptr_t timeline_vtable; // 0 = learn from the first live object
    std::uintptr_t curve_vtable;
    void (*interpolate_curve)(void*, int, float);
    void (*cleanup_curve)(void*);
    void (*stop_timeline)(void*);
    int (*target_type)(void*);
};

class Adapter {
    mutable Engine engine;

    bool describe(void* event, void*& timeline, CurveView& curve) const noexcept {
        if (!event) return false;
        const auto event_vt = field<std::uintptr_t>(event, 0);
        if (!engine.curve_vtable) engine.curve_vtable = event_vt;
        if (event_vt != engine.curve_vtable) return false;
        auto track = field<void*>(event, 0x28);
        if (!track) return false;
        timeline = field<void*>(track, 0x40);
        if (!timeline) return false;
        const auto tl_vt = field<std::uintptr_t>(timeline, 0);
        if (!engine.timeline_vtable) engine.timeline_vtable = tl_vt;
        if (tl_vt != engine.timeline_vtable) return false;
        auto target = field<void*>(track, 0x28);
        if (!target) return false;
        curve = {field<std::int32_t>(event, 0x8),
                 field<std::int32_t>(event, 0xC),
                 field<std::int32_t>(event, 0x38),
                 field<std::uint8_t>(event, 0x60) != 0,
                 engine.target_type(target) == 0x2B};
        return true;
    }

public:
    explicit Adapter(Engine e) noexcept : engine(e) {}

    void interpolate(void* event, int pass, float frame) const {
        void* timeline = nullptr;
        CurveView curve{};
        if (describe(event, timeline, curve)) {
            const auto decision = interpolation(curve,
                field<std::int32_t>(timeline, 0x1D8), pass, frame);
            if (decision != Decision::original) return;
        }
        engine.interpolate_curve(event, pass, frame);
    }

    void stop(void* timeline) const {
        if (timeline && !engine.timeline_vtable)
            engine.timeline_vtable = field<std::uintptr_t>(timeline, 0);
        engine.stop_timeline(timeline);
        if (!timeline || field<std::uintptr_t>(timeline, 0) != engine.timeline_vtable) return;
        auto tracks = field<void**>(timeline, 0x700);
        auto count = field<std::uint64_t>(timeline, 0x708);
        for (std::uint64_t i = 0; i < count; ++i) {
            void* track = tracks[i];
            if (!track || field<void*>(track, 0x40) != timeline) continue;
            auto events = field<void**>(track, 0);
            auto event_count = field<std::uint64_t>(track, 0x8);
            for (std::uint64_t j = 0; j < event_count; ++j) {
                void* owner = nullptr;
                CurveView curve{};
                if (describe(events[j], owner, curve) && owner == timeline
                    && needs_terminal_cleanup(curve))
                    engine.cleanup_curve(events[j]);
            }
        }
    }

    bool request_forced_mode(void* timeline) const noexcept {
        const bool requested = field<std::uint8_t>(timeline, 0x774) != 0;
        if (!timeline) return requested;
        const auto vt = field<std::uintptr_t>(timeline, 0);
        if (!engine.timeline_vtable) engine.timeline_vtable = vt;
        if (vt != engine.timeline_vtable) return requested;
        return false;
    }
};
}
