#pragma once
#include <cstdint>
struct QBPatch {
    std::uint64_t address;
    std::uint32_t length;
    std::uint8_t original[16];
    std::uint8_t replacement[16];
};
struct QBPlan {
    std::uint32_t version;
    std::uint32_t count;
    std::uint64_t image;
    std::uint64_t relay;
    QBPatch patches[4];
};
static_assert(sizeof(QBPatch) == 48);
static_assert(sizeof(QBPlan) == 216);
