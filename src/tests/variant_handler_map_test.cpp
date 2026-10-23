// Copyright 2026 reFuzz project author -------youngkk.
//
// variant_handler_map_test — the live per_call variant->handler accumulator:
// function-map load, per-call attribution by syscall_id, distinct-function dedup
// within a call, executed/empty skipping, exec-count, and flush format.

#include "refuzz/feedback/binding/variant_handler_map.hpp"
#include "refuzz/feedback/observation/kernel_observation.hpp"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

using refuzz::fuzzer::KernelCallObservation;
using refuzz::fuzzer::KernelExecutionObservation;
using refuzz::fuzzer::VariantHandlerMap;

static std::string slurp(const std::string& p)
{
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

int main()
{
    // function_block_map: xfs_handler@0x1000(10), drm_handler@0x2000(4), shared@0x3000(8)
    const std::string map = "/tmp/vhm_test_map.tsv";
    {
        std::ofstream o(map);
        o << "0000000000001000\t10\txfs_handler\n"
          << "0000000000002000\t4\tdrm_handler\n"
          << "0000000000003000\t8\tshared\n";
    }

    VariantHandlerMap vhm;
    assert(vhm.LoadFunctionMap(map));
    vhm.SetVariantNames({"call0", "call1", "call2", "call3", "call4", "call5",
                         "call6", "call7", "call8", "call9", "ioctl$xfs",
                         " doesn't matter ", "", "", "", "", "", "", "", "",
                         "ioctl$drm"});

    // Build one execution: 3 calls.
    KernelExecutionObservation obs;
    {
        KernelCallObservation c;  // variant 10: hits xfs_handler (twice -> dedup) + shared
        c.syscall_id = 10;
        c.executed = true;
        c.coverage_hashes = {0x1000, 0x1008, 0x3000};  // 0x1000+0x1008 both in xfs_handler
        obs.per_call.push_back(c);
    }
    {
        KernelCallObservation c;  // variant 20: hits drm_handler + shared
        c.syscall_id = 20;
        c.executed = true;
        c.coverage_hashes = {0x2000, 0x3004};
        obs.per_call.push_back(c);
    }
    {
        KernelCallObservation c;  // NOT executed -> must be skipped
        c.syscall_id = 30;
        c.executed = false;
        c.coverage_hashes = {0x1000};
        obs.per_call.push_back(c);
    }

    vhm.OnExec(obs);
    assert(vhm.variant_count() == 2);  // only variants 10 and 20 (30 skipped)

    vhm.OnExec(obs);  // second exec -> counts double
    assert(vhm.variant_count() == 2);

    const std::string out = "/tmp/vhm_test_out.jsonl";
    assert(vhm.Flush(out));
    std::string txt = slurp(out);

    // variant 10 -> name "ioctl$xfs", execs 2, xfs_handler hit twice (dedup: once/exec),
    // shared hit twice. variant 20 -> "ioctl$drm".
    assert(txt.find("\"variant_id\":10") != std::string::npos);
    assert(txt.find("\"variant\":\"ioctl$xfs\"") != std::string::npos);
    assert(txt.find("\"variant\":\"ioctl$drm\"") != std::string::npos);
    assert(txt.find("\"execs\":2") != std::string::npos);
    assert(txt.find("[\"xfs_handler\",2]") != std::string::npos);  // dedup: 2 execs -> 2
    assert(txt.find("[\"drm_handler\",2]") != std::string::npos);

    // inert when no map loaded
    VariantHandlerMap empty;
    empty.OnExec(obs);
    assert(empty.variant_count() == 0);

    std::remove(map.c_str());
    std::remove(out.c_str());
    std::printf("variant_handler_map_test OK\n");
    return 0;
}
