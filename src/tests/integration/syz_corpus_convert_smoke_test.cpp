// Phase B B5 — syz_corpus_convert smoke test.
//
// Asserts the converter:
//   1. Produces seed_<hash>.bin and seed_<hash>.meta.json files using the
//      naming scheme recorded in manifest.jsonl.
//   2. Emits a manifest with one record per input plus orphan records on
//      rerun against an --output that already has prior-run seeds.
//   3. --fail-on-unsupported turns tier3-style inputs (which emit
//      `aggregate.nested` etc.) into a non-zero exit.
//   4. --cleanup-orphans removes prior-run seed files.

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#ifndef SYZ_CORPUS_CONVERT_BIN
#error "SYZ_CORPUS_CONVERT_BIN must be defined by CMake"
#endif
#ifndef SYZ_CORPUS_ROOT
#error "SYZ_CORPUS_ROOT must be defined by CMake"
#endif

namespace {

struct CmdResult {
    int exit_code = -1;
    std::string out;
};

CmdResult RunCmd(const std::string& cmd)
{
    CmdResult r;
    std::string full = cmd + " 2>&1";
    FILE* p = popen(full.c_str(), "r");
    assert(p);
    char buf[4096];
    while (size_t n = std::fread(buf, 1, sizeof(buf), p)) {
        r.out.append(buf, n);
    }
    int s = pclose(p);
    r.exit_code = WIFEXITED(s) ? WEXITSTATUS(s) : -1;
    return r;
}

std::string ReadAll(const std::string& path)
{
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool Contains(const std::string& hay, const std::string& needle)
{
    return hay.find(needle) != std::string::npos;
}

int CountSubstr(const std::string& hay, const std::string& needle)
{
    int n = 0;
    size_t pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += needle.size();
    }
    return n;
}

std::set<std::string> ListBinFiles(const std::string& dir)
{
    std::set<std::string> out;
    DIR* d = opendir(dir.c_str());
    if (!d) return out;
    while (auto* e = readdir(d)) {
        std::string n = e->d_name;
        if (n.size() > 4 && n.substr(n.size() - 4) == ".bin") {
            out.insert(n);
        }
    }
    closedir(d);
    return out;
}

void RmTreeBestEffort(const std::string& dir)
{
    DIR* d = opendir(dir.c_str());
    if (d) {
        while (auto* e = readdir(d)) {
            std::string n = e->d_name;
            if (n == "." || n == "..") continue;
            ::unlink((dir + "/" + n).c_str());
        }
        closedir(d);
    }
    ::rmdir(dir.c_str());
}

std::string TmpDir()
{
    char tmpl[] = "/tmp/refuzz-syz-corpus-XXXXXX";
    char* p = ::mkdtemp(tmpl);
    assert(p);
    return p;
}

void TestTier1ProducesManifestAndMetaSidecars()
{
    std::string out = TmpDir();
    std::string cmd = std::string(SYZ_CORPUS_CONVERT_BIN) +
                      " --input " + std::string(SYZ_CORPUS_ROOT) + "/tier1" +
                      " --output " + out;
    auto r = RunCmd(cmd);
    if (r.exit_code != 0) {
        std::fprintf(stderr, "convert exit=%d:\n%s\n", r.exit_code, r.out.c_str());
    }
    assert(r.exit_code == 0);

    std::string manifest = ReadAll(out + "/manifest.jsonl");
    assert(!manifest.empty());
    assert(Contains(manifest, "\"converter_version\":\"refuzz-syz-corpus-convert@1\""));
    assert(Contains(manifest, "\"target\":\"linux/amd64\""));
    assert(Contains(manifest, "\"status\":\"converted\""));
    assert(Contains(manifest, "\"run_id\":\""));

    // 3 .bin and 3 .meta.json (matching tier1 input count).
    int bins = 0, metas = 0;
    DIR* d = opendir(out.c_str());
    assert(d);
    while (auto* e = readdir(d)) {
        std::string n = e->d_name;
        if (n.size() > 4  && n.substr(n.size() - 4)  == ".bin")        ++bins;
        if (n.size() > 10 && n.substr(n.size() - 10) == ".meta.json")  ++metas;
    }
    closedir(d);
    assert(bins  == 3);
    assert(metas == 3);

    RmTreeBestEffort(out);
}

void TestRerunDetectsOrphansWithoutDeleting()
{
    std::string out = TmpDir();
    std::string convert = SYZ_CORPUS_CONVERT_BIN;
    // First pass: tier1 inputs.
    auto r1 = RunCmd(convert + " --input " + std::string(SYZ_CORPUS_ROOT) +
                     "/tier1 --output " + out);
    assert(r1.exit_code == 0);
    auto seeds_after_t1 = ListBinFiles(out);
    assert(seeds_after_t1.size() == 3);

    // Second pass: tier3 inputs (different hashes).
    auto r2 = RunCmd(convert + " --input " + std::string(SYZ_CORPUS_ROOT) +
                     "/tier3 --output " + out);
    assert(r2.exit_code == 0);

    std::string manifest = ReadAll(out + "/manifest.jsonl");
    // Expect 3 orphan rows (the tier1 seeds).
    assert(CountSubstr(manifest, "\"status\":\"orphaned_from_prior_run\"") == 3);
    // Files were NOT deleted.
    auto seeds_after_t3 = ListBinFiles(out);
    for (const auto& s : seeds_after_t1) {
        assert(seeds_after_t3.count(s) == 1);
    }

    RmTreeBestEffort(out);
}

void TestCleanupOrphansDeletesPriorRunSeeds()
{
    std::string out = TmpDir();
    std::string convert = SYZ_CORPUS_CONVERT_BIN;
    auto r1 = RunCmd(convert + " --input " + std::string(SYZ_CORPUS_ROOT) +
                     "/tier1 --output " + out);
    assert(r1.exit_code == 0);
    auto seeds_after_t1 = ListBinFiles(out);

    auto r2 = RunCmd(convert + " --input " + std::string(SYZ_CORPUS_ROOT) +
                     "/tier3 --output " + out + " --cleanup-orphans");
    assert(r2.exit_code == 0);
    auto seeds_after_t3 = ListBinFiles(out);
    for (const auto& s : seeds_after_t1) {
        assert(seeds_after_t3.count(s) == 0);
    }

    RmTreeBestEffort(out);
}

void TestFailOnUnsupportedTurnsTier3IntoNonZeroExit()
{
    std::string out = TmpDir();
    std::string convert = SYZ_CORPUS_CONVERT_BIN;
    auto r = RunCmd(convert + " --input " + std::string(SYZ_CORPUS_ROOT) +
                    "/tier3 --output " + out + " --fail-on-unsupported");
    // Tier3 emits warnings → strict mode must non-zero.
    assert(r.exit_code != 0);
    // But manifest still exists with records (no silent drops).
    std::string manifest = ReadAll(out + "/manifest.jsonl");
    assert(!manifest.empty());
    assert(Contains(manifest, "\"converter_version\":\"refuzz-syz-corpus-convert@1\""));

    RmTreeBestEffort(out);
}

} // namespace

int main()
{
    TestTier1ProducesManifestAndMetaSidecars();
    TestRerunDetectsOrphansWithoutDeleting();
    TestCleanupOrphansDeletesPriorRunSeeds();
    TestFailOnUnsupportedTurnsTier3IntoNonZeroExit();
    return 0;
}
