// Copyright 2026 reFuzz project author -------youngkk.

#include "refuzz/scheduler/horizon/static_belief_graph.hpp"

#include "refuzz/program/artifact.hpp"     // ProgramArtifact::As<Prog>
#include "refuzz/program/syz/prog.hpp"     // syz::Prog (calls(), Call::meta())
#include "refuzz/program/syz/target.hpp"   // SyscallMeta::name()

#include <algorithm>  // sort / unique / binary_search / upper_bound
#include <fstream>
#include <mutex>      // std::unique_lock
#include <sstream>

namespace refuzz::fuzzer {

namespace {
// headroom = (PF + frontier) / (PF + frontier + DARK·dark). PF starts an unobserved target at 1.0;
// DARK<1 makes a single dark gentle (only SUSTAINED darkness sinks it), mirroring observe.py's PRUNE_RATE.
constexpr double kHeadroomPrior = 1.0;
constexpr double kDarkRate      = 0.25;

// $auto_X is the auto-generated ABI-dup of the logical variant $X; strip "auto_" so the dynamic frontier
// evidence consolidates on ONE node and runtime call names match the (auto-canonicalized) S/P/R graph_M.
// Applied at BOTH ends — Intern (graph nodes) and IdOf (runtime Score/Observe lookups).
std::string canonVariant(const std::string& n)
{
    const auto p = n.find("$auto_");
    return p == std::string::npos ? n : n.substr(0, p + 1) + n.substr(p + 6);  // drop "auto_" after '$'
}
}  // namespace

std::uint32_t StaticBeliefGraph::Intern(const std::string& name)
{
    const std::string cn = canonVariant(name);
    auto it = id_.find(cn);
    if (it != id_.end()) {
        return it->second;
    }
    const auto id = static_cast<std::uint32_t>(id_.size());
    id_.emplace(cn, id);
    if (id >= out_.size()) {
        out_.resize(id + 1);
    }
    return id;
}

int StaticBeliefGraph::IdOf(const std::string& name) const
{
    auto it = id_.find(canonVariant(name));
    return it == id_.end() ? -1 : static_cast<int>(it->second);
}

double StaticBeliefGraph::Headroom(std::uint32_t b) const  // caller holds a (shared) lock
{
    if (b >= front_.size()) {
        return 1.0;
    }
    const double f = front_[b];
    const double d = dark_[b];
    return (kHeadroomPrior + f) / (kHeadroomPrior + f + kDarkRate * d);
}

// ---- RegionMap (PC -> containing function id) -------------------------------------------------------
bool StaticBeliefGraph::LoadRegionMap(const std::string& path)
{
    std::ifstream in(path);
    if (!in) {
        return false;  // no sibling block map -> region-precision off, Observe falls back to coarse
    }
    std::vector<std::pair<std::uint64_t, std::uint32_t>> tmp;
    std::string line;
    while (std::getline(in, line)) {
        // <pc_hex> \t <block_count> \t <func>   (one start-PC line per function)
        const std::size_t t1 = line.find('\t');
        if (t1 == std::string::npos) {
            continue;
        }
        const std::size_t t2 = line.find('\t', t1 + 1);
        if (t2 == std::string::npos) {
            continue;
        }
        std::uint64_t pc = 0;
        try {
            pc = std::stoull(line.substr(0, t1), nullptr, 16);
        } catch (...) {
            continue;
        }
        const std::string name = line.substr(t2 + 1);
        auto it = rm_name2id_.find(name);
        std::uint32_t id;
        if (it == rm_name2id_.end()) {
            id = static_cast<std::uint32_t>(rm_name2id_.size());
            rm_name2id_.emplace(name, id);
        } else {
            id = it->second;
        }
        tmp.emplace_back(pc, id);
    }
    std::sort(tmp.begin(), tmp.end());
    rm_starts_.reserve(tmp.size());
    rm_fnid_.reserve(tmp.size());
    for (const auto& pr : tmp) {
        rm_starts_.push_back(pr.first);
        rm_fnid_.push_back(pr.second);
    }
    rm_loaded_ = !rm_starts_.empty();
    return rm_loaded_;
}

int StaticBeliefGraph::FuncOf(std::uint64_t pc) const  // immutable post-load -> lock-free
{
    if (rm_starts_.empty()) {
        return -1;
    }
    auto it = std::upper_bound(rm_starts_.begin(), rm_starts_.end(), pc);
    if (it == rm_starts_.begin()) {
        return -1;  // below the first function start
    }
    return static_cast<int>(rm_fnid_[(it - rm_starts_.begin()) - 1]);
}

int StaticBeliefGraph::FuncId(const std::string& name) const
{
    auto it = rm_name2id_.find(name);
    return it == rm_name2id_.end() ? -1 : static_cast<int>(it->second);
}

// ---- load --------------------------------------------------------------------------------------------
bool StaticBeliefGraph::LoadFromTsv(const std::string& path)
{
    std::ifstream in(path);
    if (!in) {
        return false;
    }
    // region-precision: load the sibling PC→func map so Observe can test new PCs against each edge's R.
    const std::size_t slash = path.find_last_of('/');
    LoadRegionMap((slash == std::string::npos ? std::string() : path.substr(0, slash + 1))
                  + "function_block_map.tsv");

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        // V_A \t V_B \t types \t source \t rho \t alpha \t beta \t rarity \t blindness \t mass \t weight \t [r_funcs]
        std::vector<std::string> col;
        col.reserve(12);
        std::stringstream ss(line);
        std::string tok;
        while (std::getline(ss, tok, '\t')) {
            col.push_back(std::move(tok));
        }
        if (col.size() < 11 || col[0].empty() || col[1].empty()) {
            continue;
        }
        double alpha = 0.0, beta = 0.0, weight = 0.0;
        try {
            alpha  = std::stod(col[5]);
            beta   = std::stod(col[6]);
            weight = std::stod(col[10]);  // = ρ · rarity · blindness · mass · cred
        } catch (...) {
            continue;
        }
        const double denom = alpha + beta;
        const double rho = denom > 0.0 ? alpha / denom : 0.0;
        const double base = rho > 1e-12 ? weight / rho : 0.0;
        // col 12 r_funcs -> the edge's gated slice R as func ids (interned via the RegionMap; functions
        // KCOV can't observe are dropped). Empty ⇒ this edge calibrates coarsely.
        std::vector<std::uint32_t> rf;
        if (col.size() > 11 && !col[11].empty() && col[11] != "-") {
            std::stringstream rs(col[11]);
            std::string fn;
            while (std::getline(rs, fn, ',')) {
                const int fid = FuncId(fn);
                if (fid >= 0) {
                    rf.push_back(static_cast<std::uint32_t>(fid));
                }
            }
            std::sort(rf.begin(), rf.end());
            rf.erase(std::unique(rf.begin(), rf.end()), rf.end());
        }
        const std::uint32_t a = Intern(col[0]);
        const std::uint32_t b = Intern(col[1]);
        out_[a].push_back(Edge{b, alpha, beta, base, std::move(rf), alpha, beta, col[2]});
        ++edges_;
    }
    front_.assign(out_.size(), 0.0);
    dark_.assign(out_.size(), 0.0);
    src_count_ = 0;
    for (std::uint32_t a = 0; a < out_.size(); ++a) {
        if (!out_[a].empty()) {
            ++src_count_;
        }
    }
    loaded_ = edges_ > 0;
    return loaded_;
}

// ---- score (lazy: a target's headroom change reflects across all its in-edges, no recompute) ---------
double StaticBeliefGraph::Score(const std::vector<std::string>& variant_names) const
{
    std::shared_lock<std::shared_mutex> lk(mtx_);
    double s = 0.0;
    for (const auto& n : variant_names) {
        const int id = IdOf(n);
        if (id < 0) {
            continue;
        }
        for (const auto& e : out_[static_cast<std::uint32_t>(id)]) {
            const double d = e.alpha + e.beta;
            const double rho = d > 0.0 ? e.alpha / d : 0.0;
            s += rho * e.base * Headroom(e.b);
        }
    }
    return s;
}

double StaticBeliefGraph::Score(const refuzz::program::ProgramArtifact& artifact) const
{
    auto prog = artifact.As<refuzz::program::syz::Prog>();
    if (!prog) {
        return 0.0;
    }
    std::shared_lock<std::shared_mutex> lk(mtx_);
    double s = 0.0;
    for (const auto& c : prog->calls()) {
        const auto* m = c->meta();
        if (m == nullptr) {
            continue;
        }
        const int id = IdOf(m->name());
        if (id < 0) {
            continue;
        }
        for (const auto& e : out_[static_cast<std::uint32_t>(id)]) {
            const double d = e.alpha + e.beta;
            const double rho = d > 0.0 ? e.alpha / d : 0.0;
            s += rho * e.base * Headroom(e.b);
        }
    }
    return s;
}

// ---- observe (region-precise) ------------------------------------------------------------------------
void StaticBeliefGraph::Observe(const std::unordered_set<std::string>& executed,
                                const std::unordered_map<std::string, std::vector<std::uint64_t>>& new_by_variant)
{
    if (!loaded_ || executed.empty()) {
        return;
    }
    std::unordered_set<std::uint32_t> exec_ids;
    exec_ids.reserve(executed.size());
    for (const auto& n : executed) {
        const int id = IdOf(n);
        if (id >= 0) {
            exec_ids.insert(static_cast<std::uint32_t>(id));
        }
    }
    if (exec_ids.empty()) {
        return;
    }
    // Per producing variant (graph id): the sorted-uniq func ids of its NEW coverage (region-precise hit),
    // and whether it produced ANY new (coarse frontier, for headroom + fallback). FuncOf reads the
    // immutable RegionMap, so this whole pre-pass is lock-free.
    std::unordered_map<std::uint32_t, std::vector<std::uint32_t>> newfn;
    std::unordered_set<std::uint32_t> has_new;
    for (const auto& kv : new_by_variant) {
        if (kv.second.empty()) {
            continue;
        }
        const int id = IdOf(kv.first);
        if (id < 0) {
            continue;
        }
        has_new.insert(static_cast<std::uint32_t>(id));
        if (rm_loaded_) {
            std::vector<std::uint32_t> fns;
            fns.reserve(kv.second.size());
            for (const std::uint64_t pc : kv.second) {
                const int f = FuncOf(pc);
                if (f >= 0) {
                    fns.push_back(static_cast<std::uint32_t>(f));
                }
            }
            std::sort(fns.begin(), fns.end());
            fns.erase(std::unique(fns.begin(), fns.end()), fns.end());
            newfn[static_cast<std::uint32_t>(id)] = std::move(fns);
        }
    }
    std::unique_lock<std::shared_mutex> lk(mtx_);
    // (1) per-TARGET headroom (coarse: B produced ANY new), each executed variant once.
    for (const std::uint32_t v : exec_ids) {
        if (v >= front_.size()) {
            continue;
        }
        if (has_new.count(v) != 0) {
            front_[v] += 1.0;
        } else {
            dark_[v] += 1.0;
        }
    }
    // (2) per-EDGE REGION-PRECISE calibration: confirm only when B's new frontier lands in the edge's R.
    for (const std::uint32_t a : exec_ids) {
        if (a >= out_.size()) {
            continue;
        }
        for (auto& e : out_[a]) {
            if (exec_ids.count(e.b) == 0) {
                continue;  // B must have run to judge the edge
            }
            bool hit;
            if (rm_loaded_ && !e.r_funcs.empty()) {
                hit = false;
                auto it = newfn.find(e.b);
                if (it != newfn.end()) {
                    for (const std::uint32_t f : it->second) {
                        if (std::binary_search(e.r_funcs.begin(), e.r_funcs.end(), f)) {
                            hit = true;
                            break;
                        }
                    }
                }
            } else {
                hit = has_new.count(e.b) != 0;  // coarse fallback (no RegionMap / edge carries no R)
            }
            if (hit) {
                e.alpha += 1.0;
                ++stats_.confirmed;
                ++stats_.observed;
            } else {
                e.beta += 1.0;
                ++stats_.refuted;
                ++stats_.observed;
            }
        }
    }
}

StaticBeliefGraph::Stats StaticBeliefGraph::stats() const
{
    std::shared_lock<std::shared_mutex> lk(mtx_);
    return stats_;
}

bool StaticBeliefGraph::DumpPosterior(const std::string& path) const
{
    std::shared_lock<std::shared_mutex> lk(mtx_);
    if (!loaded_) {
        return false;
    }
    std::ofstream out(path);
    if (!out) {
        return false;
    }
    std::vector<std::string> name(id_.size());        // id → variant name (id_ immutable post-load)
    for (const auto& kv : id_) {
        name[kv.second] = kv.first;
    }
    out << "#V_A\tV_B\ttypes\talpha0\tbeta0\talpha\tbeta\trho0\trho_post\tobs\n";
    for (std::uint32_t a = 0; a < out_.size(); ++a) {
        for (const auto& e : out_[a]) {
            const double d0 = e.alpha0 + e.beta0;
            const double d  = e.alpha + e.beta;
            const double rho0 = d0 > 0.0 ? e.alpha0 / d0 : 0.0;       // static prior mean
            const double rhop = d > 0.0 ? e.alpha / d : 0.0;          // frontier-calibrated posterior mean
            out << name[a] << '\t' << name[e.b] << '\t' << e.types << '\t'
                << e.alpha0 << '\t' << e.beta0 << '\t' << e.alpha << '\t' << e.beta << '\t'
                << rho0 << '\t' << rhop << '\t' << (d - d0) << '\n';  // obs = confirms+refutes on this edge
        }
    }
    return true;
}

} // namespace refuzz::fuzzer
