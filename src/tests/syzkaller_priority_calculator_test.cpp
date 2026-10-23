// Copyright 2026 reFuzz project author -------youngkk.
//
// [v2 batch 3 PR-Y] SyzkallerPriorityCalculator 单测 — 4-case truth table。
//
// truth table(对应 kernel impl bit packing,详 syzkaller_priority_calculator.hpp):
//   (succeeded=true,  no_any=true)  → 0b11 = 3  最高
//   (succeeded=true,  any=true)     → 0b10 = 2
//   (succeeded=false, no_any=true)  → 0b01 = 1
//   (succeeded=false, any=true)     → 0b00 = 0  最低

#include "refuzz/feedback/priority/syzkaller_priority_calculator.hpp"
#include "refuzz/feedback/signal_attributes.hpp"

#include <cassert>
#include <cstdio>

int main()
{
    using refuzz::fuzzer::SignalAttributes;
    using refuzz::fuzzer::SyzkallerPriorityCalculator;

    std::fprintf(stdout, "Running syzkaller_priority_calculator_test...\n");

    SyzkallerPriorityCalculator calc;

    // Case 1: succeeded=true,no_any=true → 0b11 = 3
    {
        SignalAttributes a;
        a.execution_succeeded    = true;
        a.involves_special_input = false;
        assert(calc.Calculate(a) == 0b11);
    }
    // Case 2: succeeded=true,any=true → 0b10 = 2
    {
        SignalAttributes a;
        a.execution_succeeded    = true;
        a.involves_special_input = true;
        assert(calc.Calculate(a) == 0b10);
    }
    // Case 3: succeeded=false,no_any=true → 0b01 = 1
    {
        SignalAttributes a;
        a.execution_succeeded    = false;
        a.involves_special_input = false;
        assert(calc.Calculate(a) == 0b01);
    }
    // Case 4: succeeded=false,any=true → 0b00 = 0
    {
        SignalAttributes a;
        a.execution_succeeded    = false;
        a.involves_special_input = true;
        assert(calc.Calculate(a) == 0b00);
    }

    return 0;
}
