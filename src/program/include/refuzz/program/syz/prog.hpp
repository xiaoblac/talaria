// reFuzz syzkaller-equivalent IR — Prog / Call
//
// Mirrors prog.Prog and prog.Call from upstream syzkaller.

#pragma once

#include "refuzz/program/syz/arg.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace refuzz::program::syz {

class SyscallMeta;
class Target;

// Mirror of prog.CallProps.
struct CallProps {
    int  fail_nth = 0;
    bool async    = false;
    int  rerun    = 0;

    bool operator==(const CallProps&) const = default;
};

inline bool is_default_call_props(const CallProps& props)
{
    return props.fail_nth == 0 && !props.async && props.rerun == 0;
}

inline bool is_valid_call_props(const CallProps& props)
{
    return !(props.fail_nth > 0 && props.rerun > 0);
}

inline CallProps reset_call_props(const CallProps&)
{
    return {};
}

inline std::vector<CallProps> minimize_call_props(const CallProps& props)
{
    std::vector<CallProps> candidates;
    auto add_unique = [&](CallProps candidate) {
        if (candidate == props) {
            return;
        }
        if (!is_valid_call_props(candidate)) {
            return;
        }
        for (const auto& existing : candidates) {
            if (existing == candidate) {
                return;
            }
        }
        candidates.push_back(candidate);
    };

    if (!is_default_call_props(props)) {
        add_unique(reset_call_props(props));
    }

    if (props.fail_nth != 0) {
        auto candidate = props;
        candidate.fail_nth = 0;
        add_unique(candidate);
        if (props.fail_nth > 1) {
            candidate = props;
            candidate.fail_nth = props.fail_nth / 2;
            add_unique(candidate);
            candidate.fail_nth = 1;
            add_unique(candidate);
        }
    }

    if (props.async) {
        auto candidate = props;
        candidate.async = false;
        add_unique(candidate);
    }

    if (props.rerun != 0) {
        auto candidate = props;
        candidate.rerun = 0;
        add_unique(candidate);
        if (props.rerun > 1) {
            candidate = props;
            candidate.rerun = props.rerun / 2;
            add_unique(candidate);
            candidate.rerun = 1;
            add_unique(candidate);
        }
    }

    return candidates;
}

// ============================================================
// Call
// ============================================================

class Call {
public:
    Call() = default;

    const SyscallMeta*                       meta()    const { return meta_; }
    const std::vector<std::unique_ptr<Arg>>& args()    const { return args_; }
    std::vector<std::unique_ptr<Arg>>&       mutable_args()  { return args_; }
    const ResultArg*                         ret()     const { return ret_.get(); }
    ResultArg*                               mutable_ret()   { return ret_.get(); }
    const CallProps&                         props()   const { return props_; }
    const std::string&                       comment() const { return comment_; }

    void set_meta(const SyscallMeta* m)               { meta_ = m; }
    void add_arg(std::unique_ptr<Arg> a)              { args_.push_back(std::move(a)); }
    void set_args(std::vector<std::unique_ptr<Arg>> a){ args_ = std::move(a); }
    void set_ret(std::unique_ptr<ResultArg> r)        { ret_ = std::move(r); }
    void set_props(CallProps p)                       { props_ = p; }
    void set_comment(std::string c)                   { comment_ = std::move(c); }

private:
    const SyscallMeta*                meta_ = nullptr;
    std::vector<std::unique_ptr<Arg>> args_;
    std::unique_ptr<ResultArg>        ret_;
    CallProps                         props_;
    std::string                       comment_;
};

// ============================================================
// Prog
// ============================================================

class Prog {
public:
    Prog() = default;

    const Target*                            target()   const { return target_; }
    const std::vector<std::unique_ptr<Call>>& calls()   const { return calls_; }
    std::vector<std::unique_ptr<Call>>&       mutable_calls()  { return calls_; }
    const std::vector<std::string>&           comments() const { return comments_; }

    void set_target(const Target* t)        { target_ = t; }
    void add_call(std::unique_ptr<Call> c)  { calls_.push_back(std::move(c)); }
    void add_comment(std::string c)         { comments_.push_back(std::move(c)); }

private:
    const Target*                       target_ = nullptr;
    std::vector<std::unique_ptr<Call>>  calls_;
    std::vector<std::string>            comments_;
};

} // namespace refuzz::program::syz
