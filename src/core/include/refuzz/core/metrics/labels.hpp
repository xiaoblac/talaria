#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace refuzz::core::metrics {

using LabelPair = std::pair<std::string, std::string>;
using Labels = std::vector<LabelPair>;

// 规范化:按 key 字典序排序,同 key 保留最后一次出现的 value。
// 目的:{(a,1),(b,2)} 与 {(b,2),(a,1)} 视作同一 series。
Labels NormalizeLabels(Labels labels);

// 契约校验。任一违反 → std::abort(fail fast)。
// 调用点:CounterOf / GaugeOf 首次注册时内部调用,publisher 不直接调。
//   name:      ^[a-z][a-z0-9_.]*$         (点分层,无连字符/大写)
//   label key: ^[a-z_][a-z0-9_]*$
//   label val: 可打印 ASCII,不含 '"' '\\' '\n' '\r'
void ValidateName(std::string_view name);
void ValidateLabels(const Labels& labels);

} // namespace refuzz::core::metrics
