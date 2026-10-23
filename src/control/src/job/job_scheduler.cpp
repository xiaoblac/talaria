#include "refuzz/control/job/job_scheduler.hpp"

#include <utility>

namespace refuzz::control::job {

JobScheduler::JobScheduler(Deps deps) : deps_(std::move(deps)) {}

JobScheduler::~JobScheduler() { Shutdown(); }

bool JobScheduler::HasRoom() const
{
    return deps_.dispatch_window_limit > 0 &&
           awaiting_accept_.size() < deps_.dispatch_window_limit;
}

void JobScheduler::TrySubmit(std::uint64_t exec_id, const Request& req, bool exploration)
{
    // 调用方在 while(HasRoom()) 下派发,故无失败路径;submit/submit_exploration 生产路径恒被 wire。
    awaiting_accept_.insert(exec_id);
    // 在 submit 之前:此刻 req 一定会被派发(本函数无失败路径),且尚未被 transport 移走。
    if (deps_.observe_submit) {
        deps_.observe_submit(req);
    }
    if (exploration && deps_.submit_exploration) {
        deps_.submit_exploration(exec_id, req);
    } else {
        deps_.submit(exec_id, req);
    }
}

void JobScheduler::Shutdown()
{
    awaiting_accept_.clear();
}

} // namespace refuzz::control::job
