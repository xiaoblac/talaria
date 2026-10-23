// reFuzz syz_v2 mutator — ChoiceTable shared-ownership handle alias.
//
// Engine publishes via std::atomic_store on shared_ptr; readers grab
// a snapshot via std::atomic_load and hold it for the call duration.
// This alias keeps the type name short across publisher/consumer.

#pragma once

#include "refuzz/mutator/linux/syz_v2/choice_table.hpp"

#include <memory>

namespace refuzz::mutator::syz_v2 {

using ChoiceTableHandle = std::shared_ptr<const ChoiceTable>;

} // namespace refuzz::mutator::syz_v2
