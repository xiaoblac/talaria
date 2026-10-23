// Copyright 2026 reFuzz project author -------youngkk.
//
// SeedHorizonModel impl — see seed_horizon_model.hpp.

#include "refuzz/scheduler/horizon/seed_horizon_model.hpp"

#include <algorithm>

namespace refuzz::fuzzer {

void SeedHorizonModel::AddResource(const std::string& name,
                                   const std::vector<std::string>& kind_chain)
{
    Res r;
    r.name = name;
    r.kind_names = kind_chain;
    res_id_.emplace(name, static_cast<int>(res_.size()));
    res_.push_back(std::move(r));
}

void SeedHorizonModel::AddSyscall(const std::string& name,
                                  const std::vector<std::string>& produces,
                                  const std::vector<std::string>& consumes)
{
    Call c;
    c.name = name;
    c.produces_names = produces;
    c.consumes_names = consumes;
    call_.push_back(std::move(c));
}

int SeedHorizonModel::ResId(const std::string& name) const
{
    auto it = res_id_.find(name);
    return it == res_id_.end() ? -1 : it->second;
}

int SeedHorizonModel::SyscallId(const std::string& name) const
{
    auto it = call_id_.find(name);
    return it == call_id_.end() ? -1 : it->second;
}

void SeedHorizonModel::Finalize()
{
    const int nres = static_cast<int>(res_.size());
    consumers_of_.assign(nres, {});
    nmass_.assign(nres, 0.0);

    call_id_.clear();
    for (int s = 0; s < static_cast<int>(call_.size()); ++s) {
        call_id_.emplace(call_[s].name, s);  // keeps first on (rare) name collision
    }

    // Resolve resource kind-chains (skip unknown entries).
    for (auto& r : res_) {
        r.kind.clear();
        for (const auto& kn : r.kind_names) {
            const int id = ResId(kn);
            // dedup: a kind-chain may repeat a name / two names alias the same id;
            // a repeated W would double-count its branch in both leaf and downstream.
            if (id >= 0 && std::find(r.kind.begin(), r.kind.end(), id) == r.kind.end()) {
                r.kind.push_back(id);
            }
        }
        // A type always satisfies a consumer that wants exactly itself, even if
        // its declared chain omitted the self name.
        const int self = ResId(r.name);
        if (self >= 0 &&
            std::find(r.kind.begin(), r.kind.end(), self) == r.kind.end()) {
            r.kind.push_back(self);
        }
    }

    // Resolve syscall produces/consumes; derive producer/consumer counts and the
    // consumers index. Counts are per DISTINCT producing / consuming syscall.
    for (int s = 0; s < static_cast<int>(call_.size()); ++s) {
        auto& c = call_[s];
        c.produces.clear();
        c.consumes.clear();
        for (const auto& n : c.produces_names) {
            const int id = ResId(n);
            if (id >= 0 &&
                std::find(c.produces.begin(), c.produces.end(), id) == c.produces.end()) {
                c.produces.push_back(id);
            }
        }
        for (const auto& n : c.consumes_names) {
            const int id = ResId(n);
            if (id >= 0 &&
                std::find(c.consumes.begin(), c.consumes.end(), id) == c.consumes.end()) {
                c.consumes.push_back(id);
            }
        }
        for (int rid : c.produces) {
            ++res_[rid].producer_count;
        }
        for (int rid : c.consumes) {
            ++res_[rid].consumer_count;
            consumers_of_[rid].push_back(s);
        }
    }
    finalized_ = true;
}

void SeedHorizonModel::ComputeMass(
    const std::function<bool(int, int)>& realized, double gamma, int depth)
{
    const int nres = static_cast<int>(res_.size());

    // leaf[T] = Σ_{W∈chain(T)} (1/cc(W)) · #{S∈consumers(W) : the produce-T→S
    // handoff is NOT yet realized}. The mask lives here (the SR reward r).
    std::vector<double> leaf(nres, 0.0);
    for (int t = 0; t < nres; ++t) {
        double acc = 0.0;
        for (int w : res_[t].kind) {
            const int cc = res_[w].consumer_count;
            if (cc == 0) {
                continue;
            }
            int novel = 0;
            for (int s : consumers_of_[w]) {
                // The handoff's novelty is keyed on the CONSUMER'S wanted type w
                // (what s declares), NOT the scored type t. Feeding any subtype of
                // w to s realizes (w, s) for every t whose chain contains w — so a
                // subtype fed to a generic fd-consumer correctly decays the fd
                // frontier of all fd-derived types.
                if (!realized(w, s)) {
                    ++novel;
                }
            }
            acc += static_cast<double>(novel) / cc;
        }
        leaf[t] = acc;
    }

    // nmass(T) = mass(T)/producer_count(T); mass(T) = leaf(T) + γ·downstream(T),
    // downstream uses the PREVIOUS iteration's nmass (truncated Neumann series).
    auto norm = [&](int t, double mass) {
        const int pc = res_[t].producer_count;
        // pc==0: a type no syscall can produce → unreachable → carries no
        // producible value (0), not the un-amortized leaf (which could blow up a
        // downstream sum if such a type were ever reached).
        return pc > 0 ? mass / pc : 0.0;
    };
    for (int t = 0; t < nres; ++t) {
        nmass_[t] = norm(t, leaf[t]);
    }

    for (int k = 0; k < depth; ++k) {
        std::vector<double> prev = nmass_;
        for (int t = 0; t < nres; ++t) {
            double down = 0.0;
            for (int w : res_[t].kind) {
                const int cc = res_[w].consumer_count;
                if (cc == 0) {
                    continue;
                }
                double sub = 0.0;
                for (int s : consumers_of_[w]) {
                    for (int tp : call_[s].produces) {
                        sub += prev[tp];
                    }
                }
                down += sub / cc;
            }
            nmass_[t] = norm(t, leaf[t] + gamma * down);
        }
    }
}

double SeedHorizonModel::Future(const std::vector<int>& produced_res) const
{
    double f = 0.0;
    for (int t : produced_res) {
        if (t >= 0 && t < static_cast<int>(nmass_.size())) {
            f += nmass_[t];
        }
    }
    return f;
}

} // namespace refuzz::fuzzer
