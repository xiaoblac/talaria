// Copyright 2026 reFuzz project author -------youngkk.
//
// SyzkallerPriorityCalculator —— PR-Y kernel impl。详 .hpp doc。

#include "refuzz/feedback/priority/syzkaller_priority_calculator.hpp"

namespace refuzz::fuzzer {

std::uint8_t SyzkallerPriorityCalculator::Calculate(const SignalAttributes& attrs) const
{
    std::uint8_t p = 0;
    if (attrs.execution_succeeded)     p |= 0b10;  // bit1
    if (!attrs.involves_special_input) p |= 0b01;  // bit0
    return p;
}

}  // namespace refuzz::fuzzer
