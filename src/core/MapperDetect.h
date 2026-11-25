#pragma once

// Manual-mapping (mapper) image classification.
//
// A candidate is a PE image observed in kernel memory that the debugger's
// loaded module list does not own. The verdict states what was observed, not
// that the image is malicious: an unowned image can also be a driver that
// unloaded while its pages were reused, or an image allocated by a legitimate
// component. Every input here is a raw observation; the classification only
// combines them and never invents a value it was not given.

#include <cstdint>
#include <cwctype>
#include <optional>
#include <string>
#include <vector>

namespace kncore
{
inline std::wstring MapperHex(uint64_t value)
{
    static const wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring text = L"0x";
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        const unsigned nibble = static_cast<unsigned>((value >> shift) & 0xF);
        if (nibble != 0 || started || shift == 0)
        {
            started = true;
            text.push_back(digits[nibble]);
        }
    }
    return text;
}

// One retained driver-history record a candidate image is cross-referenced
// against. Each field is what !unloaded, !piddb or !cihash actually read: a
// record without a range, a timestamp or a name cannot match on that field, and
// a missing match never proves that history was erased.
struct MapperHistoryRecord
{
    std::wstring Source; // UnloadedDriver, PiDDB, CiHash
    std::wstring Name;
    uint64_t Start = 0;
    uint64_t End = 0; // exclusive
    uint32_t TimeDateStamp = 0;
    bool HasRange = false;
    bool HasTimestamp = false;
};

struct MapperImageFacts
{
    uint64_t Base = 0;
    uint64_t Size = 0;          // containing allocation/driver range
    uint64_t ImageSize = 0;     // SizeOfImage from the parsed PE headers
    std::wstring PoolTag;       // empty when the candidate came from a driver object only
    std::optional<bool> NonPaged;
    bool PeValid = false;
    std::wstring PeMessage;     // why header validation did not complete
    uint32_t TimeDateStamp = 0;
    uint16_t Machine = 0;
    std::wstring PdbPath;       // CodeView RSDS path when the mapped image kept it
    std::wstring PdbIdentity;   // RSDS GUID+age text
    std::wstring ModuleOwner;   // loaded module whose range contains Base
    bool InLoadedModuleList = false;
    // Module ownership is a statement about a list, so it is reported only when
    // the inventory behind it was read completely; otherwise the row says the
    // ownership is unverified instead of claiming that nothing owns the range.
    bool ModuleInventoryVerified = false;
    std::wstring ModuleInventoryNote;
    bool OwnsModuleBase = false; // Base is the exact start of that module
    std::wstring MatchedModule;  // loaded module with the same timestamp and image size
    bool DriverObjectLinked = false;
    std::wstring DriverObjectName;
    uint64_t DriverObject = 0;
    bool DriverStartExact = false; // the driver object's DriverStart equals Base
    // Driver-object linkage is a statement about the \Driver namespace, so an
    // absence claim needs that namespace to have been read completely. A walk that
    // stopped early leaves the linkage unverified instead of reporting that no
    // driver object points into the image.
    bool DriverObjectInventoryVerified = false;
    std::wstring DriverObjectInventoryNote;
    std::optional<bool> PageExecutable;
    std::optional<bool> PageWritable;
    bool PageRangeClassified = false;
    // True only when the permission walk covered every page of the range that bounds the
    // image. The walk is bounded, so a large image is classified from the pages that were
    // read; a conclusion that no page of the image can execute needs the whole range, and a
    // sampled prefix cannot support it.
    bool PageRangeComplete = false;
    // True when the page sweep reached this candidate and no record named it: no driver
    // object's DriverStart, no big-pool allocation and no retained unload record
    // describes the address or the range containing it. The sweep is a candidate
    // generator rather than evidence, so the reporting gate counts such a page instead
    // of turning it into a mapping row.
    bool SweepOnly = false;
    std::vector<std::wstring> Sources;
    // History cross-references. Each flag is set only by a retained record the
    // caller actually read, so an unmatched image stays unclassified rather
    // than being called clean.
    bool UnloadedDriverRangeMatch = false; // a retained unload record covers Base
    std::wstring UnloadedDriverName;
    bool DriverDatabaseMatch = false; // PiDDB timestamp or driver-name match
    std::wstring DriverDatabaseName;
    bool CiCacheMatch = false; // CI cache driver-name match
    std::wstring CiCacheName;
};

struct MapperVerdict
{
    std::wstring Classification;
    std::wstring Reason;
    std::wstring Confidence;
};

// Driver names are not normalized by the kernel or by the history tables.
inline bool MapperNameEqual(const std::wstring &left, const std::wstring &right)
{
    if (left.size() != right.size())
    {
        return false;
    }
    for (size_t index = 0; index < left.size(); ++index)
    {
        if (std::towlower(left[index]) != std::towlower(right[index]))
        {
            return false;
        }
    }
    return true;
}

// The name a retained history record can be compared with: the PDB path the
// mapped image carries, reduced to its file stem, or the loaded module whose
// build matched it. An image with neither has no name to match on.
inline std::wstring MapperMatchName(const MapperImageFacts &facts)
{
    std::wstring name = facts.PdbPath;
    const size_t separator = name.find_last_of(L"\\/");
    if (separator != std::wstring::npos)
    {
        name = name.substr(separator + 1);
    }
    if (name.size() > 4 && MapperNameEqual(name.substr(name.size() - 4), L".pdb"))
    {
        name.resize(name.size() - 4);
    }
    return name.empty() ? facts.MatchedModule : name;
}

// The identity a human can act on: the PDB path the image itself carries, the
// loaded driver whose build matches it, the history record that named it, or
// the allocation it was found in.
inline std::wstring MapperImageIdentity(const MapperImageFacts &facts)
{
    if (!facts.PdbPath.empty())
    {
        return facts.PdbPath;
    }
    if (!facts.MatchedModule.empty())
    {
        return facts.MatchedModule + L" (timestamp and image size match)";
    }
    if (!facts.DriverDatabaseName.empty())
    {
        return facts.DriverDatabaseName + L" (driver database entry)";
    }
    if (!facts.CiCacheName.empty())
    {
        return facts.CiCacheName + L" (CI cache entry)";
    }
    if (!facts.PoolTag.empty())
    {
        return L"pool tag " + facts.PoolTag;
    }
    return L"unavailable";
}

// Which retained history records this image was matched against. "none" means
// no record the collectors read described this image, not that history is gone.
inline std::wstring MapperHistoryText(const MapperImageFacts &facts)
{
    std::wstring text;
    const auto append = [&text](const wchar_t *label, const std::wstring &name)
    {
        if (!text.empty())
        {
            text += L"+";
        }
        text += label;
        if (!name.empty())
        {
            text += L"(" + name + L")";
        }
    };
    if (facts.UnloadedDriverRangeMatch)
    {
        append(L"unloaded-range", facts.UnloadedDriverName);
    }
    if (facts.DriverDatabaseMatch)
    {
        append(L"piddb", facts.DriverDatabaseName);
    }
    if (facts.CiCacheMatch)
    {
        append(L"cihash", facts.CiCacheName);
    }
    return text.empty() ? L"none" : text;
}

// An absence claim needs an inventory that describes this target: the loaded-module
// list must have been read completely, must not be empty, and must explain most of the
// driver images the target's own \Driver namespace reports. Explaining one of them is not
// enough: a list that does not explain more than half is not the inventory those images were
// loaded into, and every driver image it does not own would be reported as unowned. Both
// shapes were observed live in one session - before its list was reloaded it owned one of
// 129 driver object DriverStart values and 69 candidates became rows, and after the reload
// it owned 128 of the 129, where the single image it did not own was the mapped driver
// this command exists to find.
inline bool MapperModuleInventoryUsable(bool inventoryComplete, bool inventoryEmpty, uint64_t driverObjects,
                                       uint64_t driverObjectsOwned)
{
    if (!inventoryComplete || inventoryEmpty)
    {
        return false;
    }
    if (driverObjects == 0)
    {
        // The target's driver namespace reported nothing to compare the list against, so
        // the read status is the only evidence there is.
        return true;
    }
    return driverObjectsOwned > driverObjects / 2;
}

// The comparison behind that verdict, so a coverage gap or a summary line states how far
// the list was from the target instead of only that something was wrong. The counts are the
// ones the command reports: the driver objects read from the driver namespace and the ones
// whose DriverStart a loaded module range contained.
inline std::wstring MapperModuleInventoryDeficiencyText(uint64_t driverObjects, uint64_t driverObjectsOwned)
{
    if (driverObjects == 0)
    {
        return L"Debugger module list was read but the driver namespace reported no driver objects to compare it with";
    }
    return L"Debugger module list owns " + std::to_wstring(driverObjectsOwned) + L" of the " +
           std::to_wstring(driverObjects) + L" driver object DriverStart values, so it does not describe this target's "
           L"loaded drivers";
}

// The containing range an image was found in is not always known: a driver object
// registered by a manually mapped image commonly carries a DriverStart with no
// DriverSize, so the range stays unverified instead of being invented from the image
// headers. A driver start that equals the image base links that image whether or not
// the object carries a size.
inline bool MapperDriverStartLinks(uint64_t base, uint64_t size, uint64_t driverStart)
{
    if (driverStart == 0)
    {
        return false;
    }
    if (driverStart == base)
    {
        return true;
    }
    return size != 0 && driverStart > base && driverStart - base < size;
}

// A row reports the range that was actually read, so an unverified range is reported
// as unknown rather than as a zero-sized allocation.
inline std::wstring MapperSizeText(const MapperImageFacts &facts)
{
    return facts.Size == 0 ? std::wstring(L"unknown") : std::to_wstring(facts.Size);
}

// What the ownership observation actually established. An inventory that was not
// read completely cannot support the claim that nothing owns a range, so the verdict
// says that instead of reporting a mapping nobody verified.
inline std::wstring MapperOwnershipText(const MapperImageFacts &facts)
{
    if (facts.ModuleInventoryVerified)
    {
        return L"No loaded module owns the range";
    }
    return facts.ModuleInventoryNote.empty()
               ? L"Module ownership could not be established because the loaded-module inventory was incomplete"
               : L"Module ownership could not be established because the loaded-module inventory was incomplete: " +
                     facts.ModuleInventoryNote;
}

// What the driver-object observation actually established. The linkage claim is an
// absence claim about the target's \Driver namespace, so a namespace that was not
// read completely cannot support it and the verdict says that instead.
inline std::wstring MapperDriverLinkageText(const MapperImageFacts &facts)
{
    if (facts.DriverObjectInventoryVerified)
    {
        return L"no driver object's DriverStart lies inside it";
    }
    return facts.DriverObjectInventoryNote.empty()
               ? L"the driver-object linkage could not be established because the \\Driver namespace was not read completely"
               : L"the driver-object linkage could not be established because the \\Driver namespace was not read completely: " +
                     facts.DriverObjectInventoryNote;
}

inline MapperVerdict ClassifyMapperImage(const MapperImageFacts &facts)
{
    MapperVerdict verdict;
    if (facts.InLoadedModuleList && facts.OwnsModuleBase)
    {
        verdict.Classification = L"LoadedModuleImage";
        verdict.Reason = facts.ModuleOwner.empty()
                             ? L"The base address is a module start in the debugger module list"
                             : L"The base address is the start of the loaded module " + facts.ModuleOwner;
        verdict.Confidence = L"High";
        return verdict;
    }
    if (facts.InLoadedModuleList)
    {
        verdict.Classification = L"MappedInsideModuleRange";
        verdict.Reason = facts.ModuleOwner.empty()
                             ? L"The base address lies inside a loaded module range but is not its start"
                             : L"The base address lies inside the loaded module " + facts.ModuleOwner + L" but is not its start";
        verdict.Confidence = facts.PeValid ? L"High" : L"Medium";
        return verdict;
    }
    if (!facts.PeValid)
    {
        verdict.Classification = L"ManualMappedHeadersUnverified";
        verdict.Reason = facts.PeMessage.empty()
                             ? MapperOwnershipText(facts) + L" and its PE headers could not be validated"
                             : MapperOwnershipText(facts) + L" and its PE headers could not be validated: " + facts.PeMessage;
        verdict.Confidence = L"Low";
        return verdict;
    }
    if (!facts.ModuleInventoryVerified)
    {
        // The image is absent from the inventory that was read, but that inventory did
        // not describe the target, so the ownership stays unverified rather than becoming
        // a mapping that no module owns. These are the facts the reporting gate withholds,
        // so this classification states them without publishing a row.
        verdict.Classification = L"ManualMappedSuspectModuleOwnershipUnverified";
        verdict.Reason = MapperOwnershipText(facts);
        if (facts.DriverObjectLinked)
        {
            verdict.Reason += L"; the driver object " +
                              (facts.DriverObjectName.empty() ? std::wstring(L"object") : facts.DriverObjectName) + L" at " +
                              MapperHex(facts.DriverObject) + L" has DriverStart inside the image";
        }
        verdict.Confidence = L"Low";
        return verdict;
    }
    if (facts.DriverObjectLinked)
    {
        verdict.Classification = L"ManualMappedDriverLinked";
        verdict.Reason = L"No loaded module owns the range, and the driver object " +
                         (facts.DriverObjectName.empty() ? std::wstring(L"object") : facts.DriverObjectName) + L" at " +
                         MapperHex(facts.DriverObject) + L" has DriverStart inside the image";
        verdict.Confidence = L"High";
        return verdict;
    }
    if (facts.UnloadedDriverRangeMatch)
    {
        // The strongest benign explanation for an unowned image: the loader's own
        // record already described this range, so the pages can be that driver's
        // residue rather than a mapping nobody registered.
        verdict.Classification = L"UnloadedDriverResidue";
        verdict.Reason = MapperOwnershipText(facts) + L" and " + MapperDriverLinkageText(facts) +
                         L", but the retained unload record " +
                         (facts.UnloadedDriverName.empty() ? std::wstring(L"for this range") : facts.UnloadedDriverName) +
                         L" covers " + MapperHex(facts.Base) + L", so the pages can be that driver's residue";
        verdict.Confidence = L"Medium";
        return verdict;
    }
    verdict.Classification = L"ManualMappedDriverUnlinked";
    if (facts.DriverDatabaseMatch)
    {
        verdict.Reason = MapperOwnershipText(facts) + L" and " + MapperDriverLinkageText(facts) +
                         L", but the image build matches the retained "
                         L"driver-database entry " +
                         (facts.DriverDatabaseName.empty() ? std::wstring(L"recorded for this timestamp")
                                                          : facts.DriverDatabaseName);
        verdict.Confidence = L"High";
        return verdict;
    }
    if (facts.CiCacheMatch)
    {
        verdict.Reason = MapperOwnershipText(facts) + L" and " + MapperDriverLinkageText(facts) +
                         L", but the image name matches the retained "
                         L"CI cache entry " +
                         facts.CiCacheName;
        verdict.Confidence = L"Medium";
        return verdict;
    }
    verdict.Reason = MapperOwnershipText(facts) + L" and " + MapperDriverLinkageText(facts);
    verdict.Confidence = L"Medium";
    return verdict;
}

// Why a candidate is not reported as a mapping row. A mapping claim needs a verified PE
// image, an observation that ties the address to an image, and an inventory that can
// support the absence the row asserts. The reasons below are exactly the inputs that live
// collection turned into false positives: a module list that could not support the absence,
// pages of mapped firmware images that no record named, non-executable copies of loaded
// drivers, and a pool allocation whose first two bytes were MZ.
enum class MapperRowDrop
{
    None,                      // the candidate is reported as a mapping claim
    ModuleOwnershipUnverified, // the absence claim about the loaded-module list is unverified
    MzPrefixOnly,              // the prefix bytes matched and no PE image verified
    ImageCopyNotExecutable,    // a verified image whose whole range was walked and cannot execute
    SweepPageNoRecord,         // the sweep reached the page and no record names it
};

// Whether a candidate becomes a detection row, and if not, which observation withheld
// it. The classification above states what the facts showed; this gate states whether
// they amount to a mapping someone observed, because a table of rows is a claim about
// the target and not a list of everything that looked like an image. A row that says no
// loaded module owns an image is an absence claim about the module list, so it also needs
// that list to have described the target, which is why an unverified ownership is withheld
// instead of being reported at low confidence.
inline MapperRowDrop MapperRowDecision(const MapperImageFacts &facts)
{
    if (!facts.PeValid)
    {
        // Two bytes of a page are not an image: without verified headers the command
        // cannot tell a mapped image from an allocation that starts with MZ.
        return MapperRowDrop::MzPrefixOnly;
    }
    if (!facts.InLoadedModuleList && !facts.ModuleInventoryVerified)
    {
        // The row's claim is that no loaded module owns this image, and that claim rests on
        // an inventory that describes the target. When the list did not describe the target's
        // own driver images, every candidate it does not own would be reported as a mapping
        // nobody verified - observed live as 69 rows from a list that owned one of 129 driver
        // starts - so the candidate is withheld instead. A stale or ambiguous ownership index
        // leaves the same claim unverified and is withheld the same way, while a candidate
        // inside a loaded module's range makes no absence claim and is judged below.
        return MapperRowDrop::ModuleOwnershipUnverified;
    }
    if (facts.PageRangeComplete && facts.PageExecutable.has_value() && !*facts.PageExecutable)
    {
        // Every page of the image's range was walked and none of them can execute, so these
        // bytes are a copy of an image rather than a driver that runs. A range the bounded
        // walk only sampled keeps its row, because a prefix cannot establish that the rest of the
        // image cannot execute.
        return MapperRowDrop::ImageCopyNotExecutable;
    }
    if (facts.SweepOnly && !facts.UnloadedDriverRangeMatch && !facts.DriverDatabaseMatch && !facts.CiCacheMatch)
    {
        // Nothing the debugger read points at this page: it holds bytes whose start
        // looks like an image, and no record says an image was mapped there.
        return MapperRowDrop::SweepPageNoRecord;
    }
    return MapperRowDrop::None;
}

inline std::wstring MapperPermissionText(const MapperImageFacts &facts)
{
    if (!facts.PageExecutable && !facts.PageWritable)
    {
        return L"unknown";
    }
    std::wstring text;
    text.push_back(facts.PageWritable.value_or(false) ? L'W' : L'-');
    text.push_back(facts.PageExecutable.value_or(false) ? L'X' : L'-');
    if (!facts.PageRangeClassified)
    {
        text += L" (partial range)";
    }
    return text;
}

// One console line per candidate carrying the fields a reader needs to judge it.
inline std::wstring MapperImageText(const MapperImageFacts &facts, const MapperVerdict &verdict)
{
    std::wstring line = L"[mapper] " + verdict.Classification + L" base=" + MapperHex(facts.Base) + L" size=" +
                        MapperSizeText(facts) + L" image=" + MapperImageIdentity(facts) + L" module=";
    if (facts.InLoadedModuleList)
    {
        line += facts.ModuleOwner.empty() ? L"loaded" : facts.ModuleOwner;
    }
    else
    {
        line += facts.ModuleInventoryVerified ? L"none" : L"unverified";
    }
    line += L" driver=";
    if (facts.DriverObjectLinked)
    {
        line += facts.DriverObjectName.empty() ? L"linked" : facts.DriverObjectName;
    }
    else
    {
        line += facts.DriverObjectInventoryVerified ? L"none" : L"unverified";
    }
    line += L" history=" + MapperHistoryText(facts);
    line += L" pages=" + MapperPermissionText(facts) + L" pe=" + (facts.PeValid ? L"valid" : L"unverified");
    line += L" confidence=" + verdict.Confidence;
    return line;
}

// The counters the command's summary line carries. The line is assembled here so what a
// reader sees - the rows, the counts withheld by reason and the inventory the ownership
// claims rested on - can be tested directly instead of only through a live session.
struct MapperSummaryCounts
{
    uint64_t Candidates = 0;
    uint64_t SweepSlots = 0;
    uint64_t Rows = 0; // candidates reported as mapping claims
    uint64_t MzPrefixOnly = 0;
    uint64_t SweepPageNoRecord = 0;
    uint64_t ImageCopyNotExecutable = 0;
    uint64_t ModuleOwnershipUnverified = 0;
    uint64_t ModuleOwnedSkipped = 0;
    uint64_t DriverObjects = 0;
    uint64_t DriverStartsOwned = 0;
    uint64_t HistoryRecords = 0;
    uint64_t Modules = 0;
    bool ModuleInventoryUsable = true;
};

// One line per run. A table of rows is a claim about the target, so the line carries what
// was withheld and the comparison the ownership claims rested on, not only the rows.
inline std::wstring MapperSummaryText(const MapperSummaryCounts &counts)
{
    std::wstring line = L"[mapper] candidates=" + std::to_wstring(counts.Candidates) + L" sweepSlots=" +
                        std::to_wstring(counts.SweepSlots) + L" unowned=" + std::to_wstring(counts.Rows) +
                        L" mzPrefixOnly=" + std::to_wstring(counts.MzPrefixOnly) +
                        L" sweepPageNoRecord=" + std::to_wstring(counts.SweepPageNoRecord) +
                        L" imageCopyNotExecutable=" + std::to_wstring(counts.ImageCopyNotExecutable) +
                        L" moduleOwnershipUnverified=" + std::to_wstring(counts.ModuleOwnershipUnverified) +
                        L" moduleOwnedSkipped=" + std::to_wstring(counts.ModuleOwnedSkipped) +
                        L" driverObjects=" + std::to_wstring(counts.DriverObjects) + L" driverStartsOwned=" +
                        std::to_wstring(counts.DriverStartsOwned) + L" historyRecords=" +
                        std::to_wstring(counts.HistoryRecords) + L" modules=" + std::to_wstring(counts.Modules);
    if (!counts.ModuleInventoryUsable)
    {
        // Every withheld candidate rests on this comparison, so the line states the
        // comparison instead of only that something was wrong.
        line += L" (module inventory unusable: " +
                MapperModuleInventoryDeficiencyText(counts.DriverObjects, counts.DriverStartsOwned) + L")";
    }
    return line;
}

// The limitations the command records with its result. They are kept here so the wording
// that tells a reader what the rows do not establish is testable like the rest of the gate.
inline std::wstring MapperLimitationsText()
{
    return L"Candidates are big-pool allocations whose first bytes are MZ, the interior pages of a big-pool allocation, "
           L"driver-object DriverStart ranges, the pages a loaded module does not own next to each module range, and the ranges "
           L"retained unload records describe. A candidate is reported as a row only when its PE headers verified and a record "
           L"ties the address to an image: a driver object's DriverStart, the big-pool allocation or retained unload range that "
           L"contains it, or a retained history record that matched it. The summary line counts the rest by reason - mzPrefixOnly "
           L"for PE-shaped bytes whose image did not verify, imageCopyNotExecutable for a verified image whose whole range was "
           L"walked and holds no executable page, sweepPageNoRecord for a page the sweep reached that no record names, and "
           L"moduleOwnershipUnverified for a candidate whose absence from the loaded-module list could not be established - "
           L"because the list did not describe the target's own driver images, or because the ownership index could not "
           L"decide the address - so those counts have to be read together with the rows. None of them is a "
           L"verdict of maliciousness: an unowned image can be an unloaded driver's leftover pages or a legitimate "
           L"allocation. A history match is a cross-reference against a retained record, so a missing match does not establish "
           L"that history was erased. Page permissions come from the current CR3 and are non-atomic with the rest of the "
           L"collection. An image without a debug directory has no PDB identity to report. Module ownership is judged against "
           L"the debugger's module list and a row is withheld when that list does not describe the target's own driver "
           L"images, because a list that does not explain more than half of the target's driver object DriverStart values "
           L"cannot support the claim that nothing owns a range; those candidates are counted as moduleOwnershipUnverified "
           L"instead.";
}
} // namespace kncore
