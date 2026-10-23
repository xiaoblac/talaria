#include "refuzz/core/concepts.hpp"
#include "refuzz/core/feedback.hpp"
#include "refuzz/core/observer.hpp"
#include "refuzz/core/stage.hpp"
#include "refuzz/control/fuzzer_context.hpp"
#include "refuzz/control/stages/calibration_stage.hpp"
#include "refuzz/control/stages/mutational_stage.hpp"
#include "refuzz/feedback/evaluator/exec_result_evaluator.hpp"
#include "refuzz/feedback/observer/coverage_observer.hpp"
#include "refuzz/feedback/observer/exec_result_observer.hpp"

static_assert(refuzz::core::StageLike<refuzz::control::MutationalStage, refuzz::control::FuzzerContext>);
static_assert(refuzz::core::StageLike<refuzz::control::CalibrationStage, refuzz::control::FuzzerContext>);

using Pipeline = refuzz::core::StagePipeline<refuzz::control::FuzzerContext,
                                             refuzz::control::MutationalStage,
                                             refuzz::control::CalibrationStage>;
static_assert(Pipeline::kStageCount == 2);

using ObserverBundle = refuzz::core::ObserverSet<refuzz::fuzzer::CoverageObserver,
                                                 refuzz::fuzzer::ExecResultObserver>;
static_assert(ObserverBundle::kCount == 2);

using OrFb = refuzz::core::OrFeedback<refuzz::fuzzer::ExecResultEvaluator, refuzz::fuzzer::ExecResultEvaluator>;
static_assert(sizeof(OrFb) > 0);
