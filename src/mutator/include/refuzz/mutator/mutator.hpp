#pragma once

// mutator "伞形" 头：统一暴露 MutatorManager 与各 engine 实现。
//
// 调用方请统一使用 MutatorManager + SwitchEngineByName("syz")。

#include "refuzz/mutator/mutator_manager.hpp"
