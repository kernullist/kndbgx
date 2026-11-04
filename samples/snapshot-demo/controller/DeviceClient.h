#pragma once

#include <Windows.h>
#include <winioctl.h>
#include "../Protocol.h"

namespace knsnapshot
{
struct IoReply
{
    bool Accepted;
    DWORD Error;
    DWORD Bytes;
};

inline bool ValidState(const State &state, DWORD bytes)
{
    const bool off = state.ActivePhase == Phase::Off && state.RegisteredMask == 0;
    const bool active = (state.ActivePhase == Phase::A || state.ActivePhase == Phase::B) &&
                        state.RegisteredMask == Registration::Required && state.RegistrationStatus >= 0;
    return bytes == sizeof(state) && state.Size == sizeof(state) && state.AbiVersion == Version && state.Reserved == 0 && (off || active);
}

template <typename Call> bool ReadDeviceState(Call &call, State &state, DWORD &error, const Phase *phase = nullptr)
{
    PhaseRequest request = {sizeof(request), Version, phase != nullptr ? *phase : Phase::Off, 0};
    const auto reply = call(phase != nullptr ? SetPhase : Query, phase != nullptr ? &request : nullptr,
                            phase != nullptr ? sizeof(request) : 0, &state, sizeof(state));
    error = reply.Accepted ? ERROR_INVALID_DATA : reply.Error;
    const bool valid = reply.Accepted && reply.Error == ERROR_SUCCESS && ValidState(state, reply.Bytes) &&
                       (phase == nullptr || state.OperationStatus < 0 || state.ActivePhase == *phase);
    if (valid)
    {
        error = ERROR_SUCCESS;
    }
    return valid;
}

inline bool SameControlState(const State &first, const State &second)
{
    // Event counters can advance during a read-only observation.
    return first.ActivePhase == second.ActivePhase && first.RegisteredMask == second.RegisteredMask &&
           first.Generation == second.Generation && first.OperationStatus == second.OperationStatus &&
           first.CleanupStatus == second.CleanupStatus && first.RegistrationStatus == second.RegistrationStatus;
}

template <typename Call, typename Report> bool RunDeviceBoundaryTests(Call &call, Report report)
{
    State before = {};
    DWORD error = 0;
    if (!ReadDeviceState(call, before, error))
    {
        report(0, false, error, 0);
        return false;
    }
    const Phase phase = before.ActivePhase;
    State positive = {};
    const bool positivePassed = ReadDeviceState(call, positive, error, &phase) && positive.OperationStatus >= 0 &&
                                positive.CleanupStatus >= 0 && positive.ActivePhase == phase &&
                                positive.RegisteredMask == before.RegisteredMask && positive.Generation == before.Generation;
    report(0, positivePassed, error, 0);
    if (!positivePassed)
    {
        return false;
    }
    before = positive;
    const DWORD expectedErrors[] = {ERROR_BAD_LENGTH, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_INVALID_PARAMETER,
                                   ERROR_INVALID_PARAMETER, ERROR_INVALID_FUNCTION, ERROR_BAD_LENGTH};
    bool passed = true;
    for (unsigned test = 0; test < _countof(expectedErrors); ++test)
    {
        PhaseRequest request = {sizeof(request), Version, phase, 0};
        State output = {};
        DWORD inputLength = sizeof(request);
        DWORD outputLength = sizeof(output);
        DWORD code = SetPhase;
        switch (test)
        {
        case 0:
            --inputLength;
            break;
        case 1:
            --outputLength;
            break;
        case 2:
            ++request.AbiVersion;
            break;
        case 3:
            request.Reserved = 1;
            break;
        case 4:
            request.RequestedPhase = static_cast<Phase>(3);
            break;
        case 5:
            code = CTL_CODE(DeviceType, 0x802u, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA);
            break;
        default:
            code = Query;
            break;
        }
        const auto reply = call(code, &request, inputLength, &output, outputLength);
        State after = {};
        const bool unchanged = ReadDeviceState(call, after, error) && SameControlState(before, after);
        const bool good = !reply.Accepted && reply.Error == expectedErrors[test] && reply.Bytes == 0 && unchanged;
        report(test + 1, good, reply.Error, reply.Bytes);
        passed = good && passed;
    }
    return passed;
}
}
