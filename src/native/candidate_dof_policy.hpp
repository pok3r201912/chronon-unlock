// Experimental policy core, not an installed Quantum Break patch.
// Integration must run on the engine thread and preserve the game's ABI.
// Only CameraEntityState (type 0x2B), CurveTimelineEvent subtype 0x2.
#pragma once
#include <cstdint>

namespace qb_candidate {
enum class Decision { original, defer_end, suppress_apply };

struct CurveView {
    std::int32_t start;
    std::int32_t length;
    std::int32_t subtype;
    bool pending_end;
    bool camera_target;
};

inline Decision interpolation(const CurveView& curve, int timeline_state,
                              int pass, float frame) noexcept {
    if (!curve.camera_target || curve.subtype != 0x2)
        return Decision::original;
    const auto end = static_cast<std::int64_t>(curve.start)
                   + (curve.length > 0 ? curve.length : 1);
    const bool inside = static_cast<float>(curve.start) <= frame
                     && frame < static_cast<float>(end);
    if (timeline_state == 0x3 && pass == 0x2)
        return Decision::suppress_apply;
    if (pass == 0x0 && curve.pending_end && inside
        && (timeline_state == 0x1 || timeline_state == 0x2))
        return Decision::defer_end;
    return Decision::original;
}

inline bool needs_terminal_cleanup(const CurveView& curve) noexcept {
    return curve.camera_target && curve.subtype == 0x2 && curve.pending_end;
}
}
