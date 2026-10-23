#include "refuzz/core/metadata.hpp"

#include <cassert>
#include <string>

int main()
{
    refuzz::core::MetadataMap m;
    assert(m.Empty());
    m.Set<int>(42);
    assert(m.Size() == 1);
    assert(m.Has<int>());
    assert(*m.Get<int>() == 42);
    m.Remove<int>();
    assert(!m.Has<int>());

    m.GetOrCreate<std::string>() = "x";
    assert(*m.Get<std::string>() == "x");
    m.Clear();
    assert(m.Empty());

    // [v2 batch 3 PR-W2] MergeFrom — 同 type_index key 后写覆盖前写。

    // Case 1:disjoint keys 合并 — 两边类型互不相同,目标得到所有 key。
    {
        refuzz::core::MetadataMap a;
        a.Set<int>(1);
        refuzz::core::MetadataMap b;
        b.Set<std::string>("hello");
        a.MergeFrom(b);
        assert(a.Size() == 2);
        assert(*a.Get<int>() == 1);
        assert(*a.Get<std::string>() == "hello");
    }

    // Case 2:overlap key — other 的值覆盖 self 的同类型值。
    {
        refuzz::core::MetadataMap a;
        a.Set<int>(1);
        refuzz::core::MetadataMap b;
        b.Set<int>(99);
        a.MergeFrom(b);
        assert(a.Size() == 1);
        assert(*a.Get<int>() == 99);  // 后写(b)覆盖前写(a)
    }

    // Case 3:other 不修改 — MergeFrom 是 const-ref 输入,b 不变。
    {
        refuzz::core::MetadataMap a;
        refuzz::core::MetadataMap b;
        b.Set<int>(7);
        a.MergeFrom(b);
        assert(*b.Get<int>() == 7);
        assert(*a.Get<int>() == 7);
    }

    // Case 4:empty other 是 no-op。
    {
        refuzz::core::MetadataMap a;
        a.Set<int>(5);
        refuzz::core::MetadataMap b;
        a.MergeFrom(b);
        assert(a.Size() == 1);
        assert(*a.Get<int>() == 5);
    }

    return 0;
}
