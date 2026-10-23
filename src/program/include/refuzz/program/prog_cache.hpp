#pragma once

#include "refuzz/fuzzer/interfaces.hpp"
#include "refuzz/program/prog_codec.hpp"

#include <list>
#include <memory>
#include <unordered_map>

namespace refuzz::fuzzer {

template <typename ProgT, typename CodecT>
class ProgCache {
public:
    ProgCache(ICorpusStore& store, CodecT& codec, size_t max_size = 1024)
        : store_(store)
        , codec_(codec)
        , max_size_(max_size)
    {}

    const ProgT* Get(uint64_t seed_id)
    {
        auto it = cache_.find(seed_id);
        if (it != cache_.end()) {
            Touch(it);
            return it->second.prog.get();
        }

        const SeedHandle seed = store_.GetSeed(seed_id);
        if (!seed) {
            return nullptr;
        }

        std::unique_ptr<IProgram> base = codec_.Decode(seed->payload);
        if (!base) {
            return nullptr;
        }

        ProgT* typed = dynamic_cast<ProgT*>(base.get());
        if (typed == nullptr) {
            return nullptr;
        }
        base.release();

        Entry entry;
        entry.prog.reset(typed);
        lru_.push_front(seed_id);
        entry.lru_it = lru_.begin();
        auto [inserted_it, _] = cache_.emplace(seed_id, std::move(entry));
        EvictIfNeeded();
        return inserted_it->second.prog.get();
    }

    void Put(uint64_t seed_id, std::unique_ptr<ProgT> prog)
    {
        if (!prog) {
            return;
        }

        auto it = cache_.find(seed_id);
        if (it != cache_.end()) {
            it->second.prog = std::move(prog);
            Touch(it);
            return;
        }

        Entry entry;
        entry.prog = std::move(prog);
        lru_.push_front(seed_id);
        entry.lru_it = lru_.begin();
        cache_.emplace(seed_id, std::move(entry));
        EvictIfNeeded();
    }

    void Evict(uint64_t seed_id)
    {
        auto it = cache_.find(seed_id);
        if (it == cache_.end()) {
            return;
        }
        lru_.erase(it->second.lru_it);
        cache_.erase(it);
    }

private:
    struct Entry {
        std::unique_ptr<ProgT> prog;
        typename std::list<uint64_t>::iterator lru_it;
    };

    void Touch(typename std::unordered_map<uint64_t, Entry>::iterator it)
    {
        lru_.erase(it->second.lru_it);
        lru_.push_front(it->first);
        it->second.lru_it = lru_.begin();
    }

    void EvictIfNeeded()
    {
        while (cache_.size() > max_size_) {
            const uint64_t victim = lru_.back();
            lru_.pop_back();
            cache_.erase(victim);
        }
    }

    ICorpusStore& store_;
    CodecT& codec_;
    size_t max_size_;
    std::list<uint64_t> lru_;
    std::unordered_map<uint64_t, Entry> cache_;
};

} // namespace refuzz::fuzzer
