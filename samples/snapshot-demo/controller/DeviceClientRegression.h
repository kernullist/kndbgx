#pragma once

#include <cstring>
#include "DeviceClient.h"

namespace knsnapshot
{
template <typename Check> void TestDeviceClient(Check check)
{
    enum class Fault
    {
        None,
        RejectAllWrites,
        WrongRejection,
        MutateOnFailure,
        InconsistentState,
        TruncatedState,
        FailedOperation
    };
    const auto run = [](Fault fault)
    {
        State current = {};
        current.Size = sizeof(current);
        current.AbiVersion = Version;
        current.ActivePhase = Phase::A;
        current.RegisteredMask = Registration::Required;
        auto call = [&](DWORD code, void *input, DWORD inputLength, void *output, DWORD outputLength) -> IoReply
        {
            DWORD error = ERROR_SUCCESS;
            if (code != Query && code != SetPhase)
            {
                error = ERROR_INVALID_FUNCTION;
            }
            else if (code == SetPhase && fault == Fault::RejectAllWrites)
            {
                error = ERROR_ACCESS_DENIED;
            }
            else if (outputLength < sizeof(State))
            {
                error = ERROR_INSUFFICIENT_BUFFER;
            }
            else if ((code == Query && inputLength != 0) || (code == SetPhase && inputLength != sizeof(PhaseRequest)))
            {
                error = ERROR_BAD_LENGTH;
            }
            else if (code == SetPhase)
            {
                const auto request = *static_cast<PhaseRequest *>(input);
                if (request.Size != sizeof(request) || request.AbiVersion != Version || request.Reserved != 0 ||
                    static_cast<uint32_t>(request.RequestedPhase) > 2)
                {
                    error = ERROR_INVALID_PARAMETER;
                }
                else if (fault == Fault::FailedOperation)
                {
                    current.OperationStatus = static_cast<int32_t>(0xc0000022u);
                }
            }
            if (error != ERROR_SUCCESS)
            {
                if (fault == Fault::MutateOnFailure)
                {
                    ++current.Generation;
                }
                return {false, fault == Fault::WrongRejection ? ERROR_GEN_FAILURE : error, 0};
            }
            auto state = current;
            if (fault == Fault::InconsistentState)
            {
                state.ActivePhase = Phase::Off;
            }
            std::memcpy(output, &state, sizeof(state));
            return {true, ERROR_SUCCESS, static_cast<DWORD>(fault == Fault::TruncatedState ? sizeof(state) - 1 : sizeof(state))};
        };
        return RunDeviceBoundaryTests(call,
                                      [](unsigned, bool, DWORD, DWORD)
                                      {
                                      });
    };
    check(run(Fault::None), L"device validation positive control");
    check(!run(Fault::RejectAllWrites), L"reject-all writes cannot pass boundary validation");
    check(!run(Fault::WrongRejection), L"wrong error codes cannot pass boundary validation");
    check(!run(Fault::MutateOnFailure), L"failed requests must preserve control state");
    check(!run(Fault::InconsistentState), L"phase and registration mask must agree");
    check(!run(Fault::TruncatedState), L"truncated state replies are rejected");
    check(!run(Fault::FailedOperation), L"accepted transport cannot hide a failed operation");
    auto wrongPhase = [](DWORD, void *, DWORD, void *output, DWORD) -> IoReply
    {
        State state = {};
        state.Size = sizeof(state);
        state.AbiVersion = Version;
        state.ActivePhase = Phase::A;
        state.RegisteredMask = Registration::Required;
        std::memcpy(output, &state, sizeof(state));
        return {true, ERROR_SUCCESS, sizeof(state)};
    };
    State state = {};
    DWORD error = 0;
    const Phase requested = Phase::B;
    check(!ReadDeviceState(wrongPhase, state, error, &requested), L"successful phase replies must match the requested transition");
}
}
