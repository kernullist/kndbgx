#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <stdexcept>

namespace kncore
{
enum class ExecutionDomain
{
    Any,
    Cli,
    Ui,
    Job
};
class OwnerThread
{
  public:
    void Require() const
    {
        if (owner_ != std::this_thread::get_id())
        {
            throw std::logic_error("engine client used outside its owner thread");
        }
    }

  private:
    const std::thread::id owner_ = std::this_thread::get_id();
};

// The short endpoint lock protects lifetime only. No engine work runs under it.
class ExecutionCoordinator
{
  public:
    using Interrupt = void (*)(void *);

    bool Begin(ExecutionDomain domain = ExecutionDomain::Cli)
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        if (busy_)
        {
            return false;
        }
        busy_ = true;
        domain_ = domain;
        ++serial_;
        cancelled_.store(false);
        return true;
    }

    void End()
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        endpoint_ = nullptr;
        interrupt_ = nullptr;
        busy_ = false;
        cancelled_.store(false);
    }

    void Arm(void *endpoint, Interrupt interrupt)
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        if (busy_)
        {
            endpoint_ = endpoint;
            interrupt_ = interrupt;
            if (cancelled_.load() && interrupt_ != nullptr)
            {
                interrupt_(endpoint_);
            }
        }
    }

    void Disarm(void *expected = nullptr)
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        if (expected != nullptr && endpoint_ != expected)
        {
            return;
        }
        endpoint_ = nullptr;
        interrupt_ = nullptr;
    }

    bool Cancel(ExecutionDomain domain = ExecutionDomain::Any, uint64_t serial = 0)
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        if (!busy_ || (domain != ExecutionDomain::Any && domain != domain_) || (serial != 0 && serial != serial_))
        {
            return false;
        }
        cancelled_.store(true);
        if (interrupt_ != nullptr)
        {
            interrupt_(endpoint_);
        }
        return true;
    }

    bool Cancelled() const
    {
        return cancelled_.load();
    }

    bool Busy()
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        return busy_;
    }

    uint64_t Serial()
    {
        std::lock_guard<std::mutex> lock(endpointMutex_);
        return busy_ ? serial_ : 0;
    }

  private:
    std::mutex endpointMutex_;
    bool busy_ = false;
    ExecutionDomain domain_ = ExecutionDomain::Any;
    uint64_t serial_ = 0;
    std::atomic<bool> cancelled_{false};
    void *endpoint_ = nullptr;
    Interrupt interrupt_ = nullptr;
};

class InterruptEndpoint
{
  public:
    InterruptEndpoint(ExecutionCoordinator &coordinator, void *endpoint, ExecutionCoordinator::Interrupt interrupt)
        : coordinator_(coordinator), endpoint_(endpoint)
    {
        coordinator_.Arm(endpoint_, interrupt);
    }
    ~InterruptEndpoint()
    {
        coordinator_.Disarm(endpoint_);
    }
    InterruptEndpoint(const InterruptEndpoint &) = delete;
    InterruptEndpoint &operator=(const InterruptEndpoint &) = delete;

  private:
    ExecutionCoordinator &coordinator_;
    void *endpoint_;
};

class ExecutionLease
{
  public:
    explicit ExecutionLease(ExecutionCoordinator &coordinator, ExecutionDomain domain = ExecutionDomain::Cli)
        : coordinator_(coordinator), acquired_(coordinator.Begin(domain))
    {
    }
    ~ExecutionLease()
    {
        if (acquired_)
        {
            coordinator_.End();
        }
    }
    explicit operator bool() const
    {
        return acquired_;
    }
    ExecutionLease(const ExecutionLease &) = delete;
    ExecutionLease &operator=(const ExecutionLease &) = delete;

  private:
    ExecutionCoordinator &coordinator_;
    bool acquired_;
};
} // namespace kncore
