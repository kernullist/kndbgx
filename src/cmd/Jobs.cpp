#include "Jobs.h"
#include "Dispatcher.h"
#include "../core/Mutation.h"
#include "../util/Text.h"
#include <bcrypt.h>
#include <objbase.h>
#include <map>
#include <memory>

namespace kncmd
{
namespace
{
struct Job
{
    std::wstring Id;
    std::wstring CommandId;
    enum class Phase
    {
        Queued,
        Running,
        Completed
    };
    Phase Stage = Phase::Queued;
    kncore::Result Result;
    std::wstring ResultId;
    std::wstring Output;
    bool CancelRequested = false;
    uint64_t Serial = 0;
    uint64_t Sequence = 0;
    HANDLE Start = nullptr;
};
struct Task
{
    std::wstring Id;
    std::wstring Command;
    kncore::SessionStamp Stamp;
    HMODULE Module = nullptr;
    std::unique_ptr<kncore::ExecutionLease> Lease;
    HANDLE Start = nullptr;
    ~Task()
    {
        if (Start != nullptr)
        {
            CloseHandle(Start);
        }
    }
};
std::mutex jobsMutex;
std::map<std::wstring, Job> jobs;
std::wstring activeJob;
bool accepting = true;
uint64_t sequence = 0;

struct ComApartment
{
    HRESULT Status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~ComApartment()
    {
        if (SUCCEEDED(Status))
        {
            CoUninitialize();
        }
    }
};

struct ModuleLease
{
    HMODULE Handle = nullptr;
    ~ModuleLease()
    {
        if (Handle != nullptr)
        {
            FreeLibrary(Handle);
        }
    }
};

knjson::Value Render(const Job &job, bool includeResult)
{
    auto row = knjson::Value::MakeObject();
    row.Set(L"jobId", knjson::Value(job.Id));
    row.Set(L"commandId", knjson::Value(job.CommandId));
    row.Set(L"resultId", knjson::Value(job.ResultId));
    row.Set(L"state", knjson::Value(job.Stage == Job::Phase::Queued    ? L"Queued"
                                    : job.Stage == Job::Phase::Running ? L"Running"
                                                                       : kncore::StatusName(job.Result.State)));
    row.Set(L"cancelRequested", knjson::Value(job.CancelRequested));
    if (includeResult && job.Stage == Job::Phase::Completed)
    {
        row.Set(L"result", job.Result.ToJson());
        row.Set(L"output", knjson::Value(job.Output));
    }
    return row;
}

void RunTask(Task &task)
{
    const DWORD activated = WaitForSingleObject(task.Start, 5000);
    kncore::Result result;
    std::wstring output;
    ComApartment com;
    {
        const bool acquired = task.Lease && static_cast<bool>(*task.Lease);
        bool cancelled = false;
        {
            std::lock_guard<std::mutex> lock(jobsMutex);
            auto &job = jobs.at(task.Id);
            job.Serial = acquired ? knengine::Coordinator().Serial() : 0;
            job.Stage = Job::Phase::Running;
            job.Start = nullptr;
            cancelled = job.CancelRequested || knengine::Coordinator().Cancelled();
        }
        if (!acquired || cancelled || FAILED(com.Status) || activated != WAIT_OBJECT_0)
        {
            result.State = cancelled ? kncore::Status::Cancelled : kncore::Status::Unavailable;
            result.Error.Message = cancelled                   ? L"CancelledBeforeStart"
                                   : FAILED(com.Status)        ? L"ComInitializationFailed"
                                   : activated == WAIT_TIMEOUT ? L"StartAcknowledgementTimeout"
                                                               : L"EngineBusy";
        }
        else if (knengine::Epochs().Stamp() != task.Stamp)
        {
            result.State = kncore::Status::StaleContext;
            result.Error.Message = L"Job context changed before execution";
        }
        else
        {
            try
            {
                knengine::DbgSession session;
                session.Initialize();
                if (session.RefreshStamp() != task.Stamp)
                {
                    result.State = kncore::Status::StaleContext;
                    result.Error.Message = L"Job context changed during engine initialization";
                }
                else
                {
                    const auto dispatched = DispatchCommand(session, task.Command, &task.Stamp);
                    result = dispatched.Data;
                    result.Rows = knjson::Value::MakeArray();
                    result.Findings = knjson::Value::MakeArray();
                    {
                        std::lock_guard<std::mutex> lock(jobsMutex);
                        jobs.at(task.Id).ResultId = dispatched.ResultId;
                    }
                    output = dispatched.Output.substr(0, knutil::Utf16PrefixUnits(dispatched.Output, 512 * 1024));
                    if (output.size() < dispatched.Output.size())
                    {
                        result.Limitations.Push(knjson::Value(L"Stored console text capped at 512Ki characters"));
                    }
                }
            }
            catch (...)
            {
                result.State = kncore::Status::InternalFault;
                result.Error.Message = L"Job executor fault";
                knengine::Epochs().Fault();
            }
        }
    }
    task.Lease.reset();
    {
        std::lock_guard<std::mutex> lock(jobsMutex);
        auto &job = jobs.at(task.Id);
        job.Result = std::move(result);
        job.Output = std::move(output);
        job.Stage = Job::Phase::Completed;
        activeJob.clear();
    }
}

DWORD WINAPI JobThread(LPVOID parameter)
{
    HMODULE module = nullptr;
    {
        std::unique_ptr<Task> task(static_cast<Task *>(parameter));
        module = task->Module;
        try
        {
            RunTask(*task);
        }
        catch (...)
        {
            knengine::Epochs().Fault();
            std::lock_guard<std::mutex> lock(jobsMutex);
            auto &job = jobs.at(task->Id);
            job.Start = nullptr;
            job.Result.State = kncore::Status::InternalFault;
            job.Stage = Job::Phase::Completed;
            activeJob.clear();
        }
    }
    FreeLibraryAndExitThread(module, 0);
}

bool CancelJob(const std::wstring &id)
{
    std::lock_guard<std::mutex> lock(jobsMutex);
    const auto found = jobs.find(id);
    if (found == jobs.end() || activeJob != id)
    {
        return false;
    }
    found->second.CancelRequested = true;
    if (found->second.Start != nullptr)
    {
        SetEvent(found->second.Start);
    }
    if (found->second.Serial != 0)
    {
        knengine::Coordinator().Cancel(kncore::ExecutionDomain::Job, found->second.Serial);
    }
    return true;
}
} // namespace

bool DetachedCommand(const CommandSpec *spec)
{
    if (spec == nullptr)
    {
        return false;
    }
    const std::wstring name = spec->Name;
    return name == L"help" || name == L"version" || name == L"features" || name == L"command-schema" || name == L"policy" || name == L"submit" ||
           name == L"jobs" || name == L"job" || name == L"cancel" || name == L"results" || name == L"result-read" || name == L"history" ||
           name == L"bookmarks" || name == L"result-export";
}

void InitializeJobs()
{
    std::lock_guard<std::mutex> lock(jobsMutex);
    accepting = true;
}

void StopJobs()
{
    std::wstring id;
    {
        std::lock_guard<std::mutex> lock(jobsMutex);
        accepting = false;
        id = activeJob;
    }
    if (!id.empty())
    {
        CancelJob(id);
    }
}

bool ActivateJob(const std::wstring &id)
{
    std::lock_guard<std::mutex> lock(jobsMutex);
    const auto found = jobs.find(id);
    return found != jobs.end() && found->second.Stage == Job::Phase::Queued && found->second.Start != nullptr &&
           SetEvent(found->second.Start) != FALSE;
}

kncore::Result SubmitJob(const std::wstring &command, bool deferStart, const kncore::SessionStamp *expected)
{
    kncore::Result result;
    ParsedCommand parsed;
    if (!ParseCommand(command, &parsed) || DetachedCommand(parsed.Spec) || parsed.Spec->Support == SupportLevel::Unsupported)
    {
        result.State = kncore::Status::InvalidInput;
        result.Error.Message = parsed.Error.empty() ? L"Invalid or recursive job command" : parsed.Error;
        return result;
    }
    std::lock_guard<std::mutex> lock(jobsMutex);
    if (!accepting || !activeJob.empty() || knengine::Coordinator().Busy())
    {
        result.State = kncore::Status::Unavailable;
        result.Error.Message = L"EngineBusyOrClosing";
        return result;
    }
    unsigned char nonce[16] = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        result.State = kncore::Status::InternalFault;
        result.Error.Message = L"Job identity or module lease unavailable";
        return result;
    }
    const std::wstring id = kncore::BytesHex(nonce);
    if (jobs.size() >= 16)
    {
        const auto oldest = std::min_element(jobs.begin(), jobs.end(),
                                             [](const auto &left, const auto &right)
                                             {
                                                 return left.second.Sequence < right.second.Sequence;
                                             });
        jobs.erase(oldest);
    }
    Job job;
    job.Id = id;
    job.CommandId = parsed.Spec->Name;
    job.Sequence = ++sequence;
    result.Rows.Push(Render(job, false));
    auto task = std::make_unique<Task>();
    task->Id = id;
    task->Command = command;
    task->Stamp = expected != nullptr ? *expected : knengine::Epochs().Stamp();
    task->Lease = std::make_unique<kncore::ExecutionLease>(knengine::Coordinator(), kncore::ExecutionDomain::Job);
    if (!*task->Lease)
    {
        result.State = kncore::Status::Unavailable;
        result.Error.Message = L"EngineBusy";
        return result;
    }
    task->Start = CreateEventW(nullptr, TRUE, deferStart ? FALSE : TRUE, nullptr);
    if (task->Start == nullptr)
    {
        result.State = kncore::Status::IOError;
        result.Error.Message = L"Job start event unavailable";
        return result;
    }
    job.Start = task->Start;
    ModuleLease module;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&JobThread), &module.Handle))
    {
        result.State = kncore::Status::IOError;
        result.Error.Message = L"Module lease unavailable";
        return result;
    }
    task->Module = module.Handle;
    try
    {
        activeJob = id;
        jobs.emplace(id, std::move(job));
        HANDLE thread = CreateThread(nullptr, 0, JobThread, task.get(), 0, nullptr);
        if (thread == nullptr)
        {
            jobs.erase(id);
            activeJob.clear();
            result.State = kncore::Status::IOError;
            result.Error.Message = L"Job thread creation failed";
            return result;
        }
        task.release();
        module.Handle = nullptr;
        CloseHandle(thread);
    }
    catch (...)
    {
        jobs.erase(id);
        activeJob.clear();
        throw;
    }
    return result;
}

void JobCommand(Ctx &context)
{
    const auto &name = context.Args[0];
    if (name == L"submit")
    {
        context.Out.Details = SubmitJob(context.Request->RawArguments, false, context.ExpectedStamp);
        if (context.Out.Details.State == kncore::Status::Success)
        {
            context.Out.AddLine(L"[job] " + context.Out.Details.Rows.Items()[0].Get(L"jobId").AsString(L""));
        }
        else
        {
            context.Out.AddLine(context.Out.Details.Error.Message);
        }
        return;
    }
    if (name == L"cancel")
    {
        const bool requested = CancelJob(context.Args[1]);
        context.Out.AddLine(requested ? L"CancelRequested" : L"JobNotActive");
        if (!requested)
        {
            context.Out.Details.State = kncore::Status::Unavailable;
        }
        return;
    }
    std::lock_guard<std::mutex> lock(jobsMutex);
    for (const auto &[id, job] : jobs)
    {
        if (name == L"jobs" || id == context.Args[1])
        {
            const auto row = Render(job, name == L"job");
            context.Out.Details.Rows.Push(row);
            context.Out.AddLine(row.Write());
        }
    }
    if (name == L"job" && context.Out.Details.Rows.Items().empty())
    {
        context.Out.Fail(kncore::Status::Unavailable, L"Job was not found or has been removed from history");
    }
}
} // namespace kncmd
