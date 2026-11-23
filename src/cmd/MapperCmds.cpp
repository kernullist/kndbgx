#include "CollectorSupport.h"
#include "CmdTypes.h"
#include "PoolAcquisition.h"
#include "../core/MappedPe.h"
#include "../core/MapperDetect.h"
#include "../core/PeIdentity.h"
#include "../core/Pool.h"
#include "../engine/LayoutResolver.h"
#include "../engine/ModuleList.h"
#include "../engine/ObjectDirectory.h"
#include "../engine/PageWalk.h"
#include <algorithm>
#include <map>

namespace kncmd
{
namespace
{
// One driver object read from the target's \Driver namespace.
struct DriverObjectLink
{
    uint64_t Object = 0;
    std::wstring Name;
    uint64_t Start = 0;
    uint64_t Size = 0;
};

// A base address that is worth validating as a mapped image.
struct MapperCandidateSource
{
    uint64_t Base = 0;
    uint64_t Size = 0;
    std::wstring PoolTag;
    std::optional<bool> NonPaged;
    bool FromPool = false;
    bool FromDriverObject = false;
    // A page the sweep reached rather than a range a source named: no inventory
    // lists it, so the row records which sweep found it.
    bool FromSweep = false;
    std::wstring SweepSource;
};

// RVA-addressed view of an image that lives in target memory: the mapped image
// is read where it is, so file offsets do not apply.
class MappedImageBytes final : public kncore::ByteReader
{
  public:
    MappedImageBytes(kncore::TargetReader &reader, uint64_t base, uint64_t size) : reader_(reader), base_(base), size_(size)
    {
    }

    uint64_t Size() const override
    {
        return size_;
    }

    bool Read(uint64_t offset, std::span<unsigned char> destination) override
    {
        if (destination.empty())
        {
            return true;
        }
        if (!kncore::Contains(size_, offset, destination.size()) || !kncore::ValidRange(base_ + offset, destination.size()))
        {
            return false;
        }
        const auto read = reader_.Read(kncore::AddressSpace::Virtual, base_ + offset, destination.size());
        if (!kncore::ExactBytes(read, destination.size()))
        {
            return false;
        }
        std::memcpy(destination.data(), read.Bytes.data(), destination.size());
        return true;
    }

  private:
    kncore::TargetReader &reader_;
    uint64_t base_;
    uint64_t size_;
};

struct CodeViewInfo
{
    std::wstring Identity;
    std::wstring PdbPath;
};

std::wstring GuidText(const unsigned char *bytes)
{
    static const wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring text;
    for (int index = 0; index < 16; ++index)
    {
        if (index == 4 || index == 6 || index == 8 || index == 10)
        {
            text.push_back(L'-');
        }
        text.push_back(digits[bytes[index] >> 4]);
        text.push_back(digits[bytes[index] & 0xF]);
    }
    return text;
}

bool PrintablePath(const std::wstring &text)
{
    return !text.empty() && text.size() <= 260 &&
           std::all_of(text.begin(), text.end(),
                       [](wchar_t character)
                       {
                           return character >= 0x20 && character < 0x7f;
                       });
}

// Reads the CodeView RSDS record of an image that is mapped in target memory.
// An absent debug directory is a complete answer; a damaged one is not, so the
// caller keeps the image identity unproven instead of guessing.
CodeViewInfo ReadMappedCodeView(kncore::ByteReader &reader, const kncore::PeImage &image)
{
    CodeViewInfo info;
    const auto directory = image.DebugDirectory;
    if (directory.Size == 0 && directory.VirtualAddress == 0)
    {
        return info;
    }
    if (directory.VirtualAddress == 0 || directory.Size == 0 ||
        directory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0 || directory.Size > 64 * sizeof(IMAGE_DEBUG_DIRECTORY) ||
        !kncore::Contains(image.ImageSize, directory.VirtualAddress, directory.Size))
    {
        return info;
    }
    for (uint32_t index = 0; index < directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++index)
    {
        IMAGE_DEBUG_DIRECTORY entry = {};
        if (!reader.ReadObject(uint64_t(directory.VirtualAddress) + uint64_t(index) * sizeof(entry), &entry))
        {
            return info;
        }
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        {
            continue;
        }
        if (entry.SizeOfData < 24 || entry.SizeOfData > 4096 ||
            !kncore::Contains(image.ImageSize, entry.AddressOfRawData, entry.SizeOfData))
        {
            return info;
        }
        std::vector<unsigned char> record(entry.SizeOfData, 0);
        if (!reader.Read(entry.AddressOfRawData, record))
        {
            return info;
        }
        if (std::memcmp(record.data(), "RSDS", 4) != 0)
        {
            continue;
        }
        info.Identity = GuidText(record.data() + 4);
        std::string raw;
        for (size_t offset = 24; offset < record.size() && record[offset] != 0; ++offset)
        {
            raw.push_back(static_cast<char>(record[offset]));
        }
        if (!raw.empty() && raw.size() <= 260)
        {
            const int wide = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data(), static_cast<int>(raw.size()), nullptr, 0);
            if (wide > 0)
            {
                std::wstring text(static_cast<size_t>(wide), L'\0');
                if (MultiByteToWideChar(CP_UTF8, 0, raw.data(), static_cast<int>(raw.size()), text.data(), wide) == wide &&
                    PrintablePath(text))
                {
                    info.PdbPath = text;
                }
            }
        }
        return info;
    }
    return info;
}

// Enumerates \Driver and reads the DriverStart/DriverSize that link an image to
// a driver object. A driver object is the only kernel structure that names a
// manually mapped image, so a missing namespace is recorded as a coverage gap.
bool CollectDriverObjects(Ctx &ctx, kncore::WalkBudget &budget, knengine::LayoutResolver &layout, kncore::TargetReader &reader,
                          std::vector<DriverObjectLink> &objects, std::wstring *note)
{
    knengine::ObjectDirectoryWalker walker(ctx.Session);
    unsigned driverType = 0;
    if (!walker.Initialize() || !walker.ResolveTypeIndex(L"Driver", &driverType))
    {
        UnknownScope(ctx, budget, L"DriverNamespace", L"Driver object type index unavailable");
        *note = L"Driver object type index unavailable";
        return false;
    }
    const auto startField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverStart");
    const auto sizeField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverSize");
    const auto nameField = layout.Field(L"nt", L"_DRIVER_OBJECT", L"DriverName");
    if (!startField || !sizeField)
    {
        UnknownScope(ctx, budget, L"DriverNamespace", L"Matched _DRIVER_OBJECT DriverStart/DriverSize metadata unavailable");
        *note = L"Matched _DRIVER_OBJECT DriverStart/DriverSize metadata unavailable";
        return false;
    }
    std::wstring error;
    const bool walked = walker.VisitDirectoryNamed(
        L"Driver",
        [&](ULONG64 body, const std::wstring &entryName)
        {
            if (!CheckCollection(ctx, budget))
            {
                return false;
            }
            unsigned type = 0;
            if (!walker.ObjectTypeIndex(body, &type) || type != driverType)
            {
                ++budget.Report.Collected.Unknown;
                return true;
            }
            const auto start = kncore::ReadField(reader, body, startField);
            const auto size = kncore::ReadField(reader, body, sizeField);
            if (!start || !size)
            {
                ++budget.Report.Collected.Unknown;
                return true;
            }
            ++budget.Report.Collected.Read;
            DriverObjectLink link;
            link.Object = body;
            link.Start = *start;
            link.Size = *size;
            std::wstring name;
            if (nameField && kncore::ValidRange(body, static_cast<uint64_t>(nameField->Offset) + nameField->Size) &&
                ReadUnicodeString(ctx.Session, layout, body + nameField->Offset, &name))
            {
                link.Name = name;
            }
            if (link.Name.empty())
            {
                link.Name = entryName;
            }
            objects.push_back(link);
            return true;
        },
        &error);
    // A row's driver-object linkage is an absence claim about this namespace, so a
    // namespace that was not read completely is recorded as a coverage gap and leaves
    // every row's linkage unverified instead of claiming that nothing points into the
    // image. The walker's own report carries why the walk stopped.
    const auto walkReport = walker.Report();
    if (walked && walkReport.Collected.Complete)
    {
        return true;
    }
    std::wstring reason = !error.empty() ? error : walkReport.Collected.StopReason;
    if (reason.empty())
    {
        reason = L"Driver object namespace walk did not complete";
    }
    UnknownScope(ctx, budget, L"DriverNamespace", L"Driver object namespace not read completely: " + reason);
    *note = L"Driver object namespace not read completely: " + reason;
    return false;
}

// Two retained records disagreeing about the driver name leave the row with the
// match but without a name, instead of picking one of them.
std::wstring UniqueHistoryName(const std::vector<std::wstring> &names)
{
    if (names.empty())
    {
        return std::wstring();
    }
    for (size_t index = 1; index < names.size(); ++index)
    {
        if (!kncore::MapperNameEqual(names[0], names[index]))
        {
            return std::wstring();
        }
    }
    return names[0];
}

// Cross-references the retained !unloaded, !piddb and !cihash records against
// one candidate image. Each source is matched on the field that identifies an
// image: an unload record on the address range it retained, a PiDDB entry on
// the raw PE timestamp (or on the driver name), and a CI cache entry on the
// name. A record that does not carry the field cannot produce that match, and
// an image nothing matched stays unclassified rather than being called clean.
void ApplyHistoryMatches(const std::vector<kncore::MapperHistoryRecord> &history, kncore::MapperImageFacts *facts)
{
    const std::wstring name = kncore::MapperMatchName(*facts);
    std::vector<std::wstring> unloadedNames;
    std::vector<std::wstring> stampNames;
    std::vector<std::wstring> driverNames;
    std::vector<std::wstring> ciNames;
    for (const auto &record : history)
    {
        if (record.Source == L"UnloadedDriver")
        {
            if (record.HasRange && facts->Base >= record.Start && facts->Base < record.End)
            {
                facts->UnloadedDriverRangeMatch = true;
                if (!record.Name.empty())
                {
                    unloadedNames.push_back(record.Name);
                }
            }
        }
        else if (record.Source == L"PiDDB")
        {
            if (record.HasTimestamp && facts->PeValid && record.TimeDateStamp != 0 &&
                record.TimeDateStamp == facts->TimeDateStamp)
            {
                facts->DriverDatabaseMatch = true;
                if (!record.Name.empty())
                {
                    stampNames.push_back(record.Name);
                }
            }
            else if (!name.empty() && !record.Name.empty() && kncore::MapperNameEqual(name, record.Name))
            {
                facts->DriverDatabaseMatch = true;
                driverNames.push_back(record.Name);
            }
        }
        else if (record.Source == L"CiHash")
        {
            if (!name.empty() && !record.Name.empty() && kncore::MapperNameEqual(name, record.Name))
            {
                facts->CiCacheMatch = true;
                ciNames.push_back(record.Name);
            }
        }
    }
    facts->UnloadedDriverName = UniqueHistoryName(unloadedNames);
    facts->DriverDatabaseName = UniqueHistoryName(stampNames.empty() ? driverNames : stampNames);
    facts->CiCacheName = UniqueHistoryName(ciNames);
    if (facts->UnloadedDriverRangeMatch)
    {
        facts->Sources.push_back(L"UnloadedDriverRange");
    }
    if (facts->DriverDatabaseMatch)
    {
        facts->Sources.push_back(L"PiDdbMatch");
    }
    if (facts->CiCacheMatch)
    {
        facts->Sources.push_back(L"CiHashMatch");
    }
}

knjson::Value MapperImageRow(const kncore::MapperImageFacts &facts, const kncore::MapperVerdict &verdict)
{
    auto row = knjson::Value::MakeObject();
    row.Set(L"kind", knjson::Value(L"MapperImage"));
    row.Set(L"baseAddress", knjson::Value(kncore::Hex(facts.Base)));
    row.Set(L"size", facts.Size == 0 ? knjson::Value() : knjson::Value(std::to_wstring(facts.Size)));
    row.Set(L"imageSize", facts.PeValid ? knjson::Value(std::to_wstring(facts.ImageSize)) : knjson::Value());
    row.Set(L"imageIdentity", knjson::Value(kncore::MapperImageIdentity(facts)));
    row.Set(L"pdbPath", facts.PdbPath.empty() ? knjson::Value() : knjson::Value(facts.PdbPath));
    row.Set(L"pdbIdentity", facts.PdbIdentity.empty() ? knjson::Value() : knjson::Value(facts.PdbIdentity));
    row.Set(L"matchedModule", facts.MatchedModule.empty() ? knjson::Value() : knjson::Value(facts.MatchedModule));
    row.Set(L"machine", facts.PeValid ? knjson::Value(kncore::Hex(facts.Machine)) : knjson::Value());
    row.Set(L"timeDateStamp", facts.PeValid ? knjson::Value(kncore::Hex(facts.TimeDateStamp)) : knjson::Value());
    row.Set(L"inLoadedModuleList", knjson::Value(facts.InLoadedModuleList));
    row.Set(L"owningModule", facts.ModuleOwner.empty() ? knjson::Value() : knjson::Value(facts.ModuleOwner));
    row.Set(L"moduleBaseMatch", knjson::Value(facts.OwnsModuleBase));
    row.Set(L"moduleInventoryVerified", knjson::Value(facts.ModuleInventoryVerified));
    row.Set(L"moduleOwnership", knjson::Value(kncore::MapperOwnershipText(facts)));
    row.Set(L"driverObjectLinked", knjson::Value(facts.DriverObjectLinked));
    row.Set(L"driverObject", facts.DriverObjectLinked ? knjson::Value(kncore::Hex(facts.DriverObject)) : knjson::Value());
    row.Set(L"driverObjectName", facts.DriverObjectName.empty() ? knjson::Value() : knjson::Value(facts.DriverObjectName));
    row.Set(L"driverStartExact", facts.DriverObjectLinked ? knjson::Value(facts.DriverStartExact) : knjson::Value());
    row.Set(L"driverObjectInventoryVerified", knjson::Value(facts.DriverObjectInventoryVerified));
    row.Set(L"pageWritable", facts.PageWritable ? knjson::Value(*facts.PageWritable) : knjson::Value());
    row.Set(L"pageExecutable", facts.PageExecutable ? knjson::Value(*facts.PageExecutable) : knjson::Value());
    row.Set(L"pagePermissions", knjson::Value(kncore::MapperPermissionText(facts)));
    row.Set(L"pageRangeClassified", knjson::Value(facts.PageRangeClassified));
    row.Set(L"poolTag", facts.PoolTag.empty() ? knjson::Value() : knjson::Value(facts.PoolTag));
    row.Set(L"nonPaged", facts.NonPaged ? knjson::Value(*facts.NonPaged) : knjson::Value());
    row.Set(L"peHeadersValid", knjson::Value(facts.PeValid));
    row.Set(L"peMessage", facts.PeMessage.empty() ? knjson::Value() : knjson::Value(facts.PeMessage));
    row.Set(L"unloadedDriverRangeMatch", knjson::Value(facts.UnloadedDriverRangeMatch));
    row.Set(L"unloadedDriverName", facts.UnloadedDriverName.empty() ? knjson::Value() : knjson::Value(facts.UnloadedDriverName));
    row.Set(L"driverDatabaseMatch", knjson::Value(facts.DriverDatabaseMatch));
    row.Set(L"driverDatabaseName", facts.DriverDatabaseName.empty() ? knjson::Value() : knjson::Value(facts.DriverDatabaseName));
    row.Set(L"ciCacheMatch", knjson::Value(facts.CiCacheMatch));
    row.Set(L"ciCacheName", facts.CiCacheName.empty() ? knjson::Value() : knjson::Value(facts.CiCacheName));
    row.Set(L"history", knjson::Value(kncore::MapperHistoryText(facts)));
    auto sources = knjson::Value::MakeArray();
    for (const auto &source : facts.Sources)
    {
        sources.Push(knjson::Value(source));
    }
    row.Set(L"sources", sources);
    row.Set(L"verdict", knjson::Value(verdict.Classification));
    row.Set(L"verdictReason", knjson::Value(verdict.Reason));
    row.Set(L"confidence", knjson::Value(verdict.Confidence));
    return row;
}
} // namespace

// Finds PE images that are present in kernel memory but absent from the loaded
// module list, and reports the evidence that ties each one to a driver object,
// an allocation, a set of page permissions and the retained driver history.
// `history` is the unloaded-driver, PiDDB and CI cache observation set that the
// composite command already collected; it supplies both extra candidates and
// the cross-reference each row is judged against. Every read is a target read.
void ScanMapperImages(Ctx &ctx, const std::vector<kncore::MapperHistoryRecord> &history)
{
    kncore::WalkBudget budget;
    kncore::TargetArchitecture architecture;
    if (!BeginCollection(ctx, budget, architecture, L"TargetMemory:PoolBigPageTable+DriverNamespace+ModuleList+PageTables"))
    {
        return;
    }
    kncore::CollectionReadGuard reader(ctx.Session, budget);
    knengine::LayoutResolver layout(ctx.Session, reader);

    std::vector<kncore::BigPoolEntry> entries;
    if (!CollectTargetBigPool(ctx, budget, architecture, entries))
    {
        return;
    }
    std::vector<DriverObjectLink> drivers;
    std::wstring driverNamespaceNote;
    const bool driverNamespaceVerified = CollectDriverObjects(ctx, budget, layout, reader, drivers, &driverNamespaceNote);

    std::vector<knengine::KernelModuleInfo> modules;
    kncore::Result inventory;
    const auto owners = knengine::CollectOwnershipIndex(ctx.Session, &modules, &inventory);
    // The debugger's module list must describe this target's loaded drivers. A list
    // that owns none of the driver objects' DriverStart values is not the inventory
    // those images were loaded into - observed live as a session whose module list had
    // not been reloaded, where every loaded driver was reported as a mapping - so the
    // absence claims stay unverified until the list describes the target.
    uint64_t driverStartsOwned = 0;
    for (const auto &driver : drivers)
    {
        if (driver.Start != 0 && owners.Find(driver.Start, budget.Report.Stamp).Image)
        {
            ++driverStartsOwned;
        }
    }
    const bool moduleInventoryUsable =
        kncore::MapperModuleInventoryUsable(inventory.Collected.Complete, modules.empty(), drivers.size(), driverStartsOwned);
    if (!moduleInventoryUsable)
    {
        UnknownScope(ctx, budget, L"LoadedModules",
                     inventory.Collected.StopReason.empty()
                         ? L"Debugger module list does not describe this target's loaded drivers"
                         : inventory.Collected.StopReason);
    }

    ULONG64 dtb = ctx.Session.ContextDtb();
    const bool dtbKnown = ctx.Session.HasContextDtb() || ctx.Session.ReadRegisterHex(L"cr3", &dtb);

    // Candidate sources keyed by base address, so one image is evaluated once.
    // A driver object that points into an image is the strongest signal; the
    // big-pool slots carry the allocation an image would occupy.
    std::map<uint64_t, MapperCandidateSource> candidates;
    for (const auto &driver : drivers)
    {
        // DriverSize is not a precondition: a driver registered by a manually mapped
        // image commonly carries a DriverStart with no size, and skipping it would hide
        // exactly the image this command looks for.
        if (driver.Start == 0 || !architecture.KernelPointer(driver.Start))
        {
            continue;
        }
        MapperCandidateSource candidate;
        candidate.Base = driver.Start;
        candidate.Size = driver.Size;
        candidate.FromDriverObject = true;
        candidates.emplace(driver.Start, candidate);
    }
    for (const auto &entry : entries)
    {
        if (entry.Size < sizeof(IMAGE_DOS_HEADER))
        {
            continue;
        }
        const auto existing = candidates.find(entry.Address);
        if (existing != candidates.end())
        {
            existing->second.FromPool = true;
            existing->second.Size = std::max<uint64_t>(existing->second.Size, entry.Size);
            existing->second.PoolTag.assign(entry.Tag.begin(), entry.Tag.end());
            if (entry.NonPagedKnown)
            {
                existing->second.NonPaged = entry.NonPaged;
            }
            continue;
        }
        MapperCandidateSource candidate;
        candidate.Base = entry.Address;
        candidate.Size = entry.Size;
        candidate.PoolTag.assign(entry.Tag.begin(), entry.Tag.end());
        if (entry.NonPagedKnown)
        {
            candidate.NonPaged = entry.NonPaged;
        }
        candidate.FromPool = true;
        candidates.emplace(entry.Address, candidate);
    }

    // A retained unload record names a base where a driver image used to live.
    // When those pages still hold an MZ image that no module owns now, the
    // history record is what pointed at it, so it becomes a candidate source
    // and not only an explanation of one found elsewhere.
    for (const auto &record : history)
    {
        if (record.Source != L"UnloadedDriver" || !record.HasRange || !architecture.KernelPointer(record.Start) ||
            !architecture.KernelPointer(record.End - 1))
        {
            continue;
        }
        if (candidates.find(record.Start) != candidates.end())
        {
            continue;
        }
        MapperCandidateSource candidate;
        candidate.Base = record.Start;
        candidate.Size = record.End - record.Start;
        candidate.FromPool = true;
        candidates.emplace(record.Start, candidate);
    }

    // A manually mapped image is not always where a source the debugger already
    // knows about begins: a mapper can place the image at a page offset inside a
    // big-pool allocation, and an image mapped into the kernel image region has no
    // allocation behind it at all. Both are reached by probing the 4 KB pages no
    // loaded module owns - the interior pages of a big-pool allocation and the pages
    // around each loaded module - because a page only becomes a row when an MZ header
    // is read there. One probe is one two-byte read, so the sweep stays affordable
    // and every page it does reach is reported.
    size_t sweepSlots = 0;
    {
        constexpr uint64_t kPageSize = 4096;
        constexpr uint64_t kEdgePages = 128; // 512 KB on each side of a module
        constexpr size_t kMaxPoolInteriorSlots = 8192;
        constexpr size_t kMaxModuleEdgeSlots = 32768;
        const auto sweepPage = [&](uint64_t base, uint64_t containingSize, const kncore::BigPoolEntry *entry)
        {
            if (!architecture.KernelPointer(base) || candidates.find(base) != candidates.end())
            {
                return;
            }
            if (owners.Find(base, budget.Report.Stamp).Image)
            {
                return;
            }
            MapperCandidateSource candidate;
            candidate.Base = base;
            candidate.FromSweep = true;
            if (entry != nullptr)
            {
                candidate.Size = containingSize;
                candidate.PoolTag.assign(entry->Tag.begin(), entry->Tag.end());
                if (entry->NonPagedKnown)
                {
                    candidate.NonPaged = entry->NonPaged;
                }
                candidate.FromPool = true;
                candidate.SweepSource = L"PoolInteriorPage";
            }
            else
            {
                candidate.SweepSource = L"ModuleRegionPage";
            }
            candidates.emplace(base, candidate);
            ++sweepSlots;
        };

        // The interior of an allocation the pool table does describe, so an image
        // placed after the allocation's own start is still evaluated.
        for (const auto &entry : entries)
        {
            if (entry.Size < kPageSize * 2)
            {
                continue;
            }
            const uint64_t pages = std::min<uint64_t>(entry.Size / kPageSize, 9);
            for (uint64_t page = 1; page < pages; ++page)
            {
                if (sweepSlots >= kMaxPoolInteriorSlots)
                {
                    break;
                }
                sweepPage(entry.Address + page * kPageSize, entry.Size, &entry);
            }
        }

        // The pages a loaded module does not own next to a module range, where a
        // manually mapped image is normally placed and no inventory lists it.
        for (const auto &module : modules)
        {
            if (module.Base == 0 || module.Size == 0 || !architecture.KernelPointer(module.Base))
            {
                continue;
            }
            const uint64_t end = module.Base + module.Size;
            for (uint64_t step = 0; step < kEdgePages; ++step)
            {
                if (sweepSlots >= kMaxPoolInteriorSlots + kMaxModuleEdgeSlots)
                {
                    break;
                }
                sweepPage(module.Base - (step + 1) * kPageSize, 0, nullptr);
                sweepPage(end + step * kPageSize, 0, nullptr);
            }
        }
    }

    // Probing a slot is one target read, so a large table cannot be swept in a
    // short window. A mapped image occupies one allocation, so the big
    // allocations are the ones worth reading first, and every candidate is
    // reported the moment it is evaluated: a sweep that stops on its budget
    // still shows each image it did reach instead of discarding them.
    std::vector<const MapperCandidateSource *> ordered;
    ordered.reserve(candidates.size());
    for (const auto &pair : candidates)
    {
        ordered.push_back(&pair.second);
    }
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const MapperCandidateSource *left, const MapperCandidateSource *right)
                     {
                         const auto rank = [](const MapperCandidateSource *source)
                         {
                             if (source->FromDriverObject)
                             {
                                 return 0;
                             }
                             return source->FromSweep ? 1 : 2;
                         };
                         if (rank(left) != rank(right))
                         {
                             return rank(left) < rank(right);
                         }
                         return left->Size > right->Size;
                     });

    // Big-pool acquisition runs on its own acquisition window; the probe sweep
    // is the expensive half of this command and gets the deep-scan window. One probe
    // is the collection unit here, so the coverage denominator is the candidate set
    // rather than the pool entries that fed it.
    budget.Report.Collected.Expected = ordered.size();
    budget.Deadline = std::chrono::steady_clock::now() + std::chrono::seconds(300);
    budget.MaxNodes = std::max<uint64_t>(budget.MaxNodes, ordered.size() + 4096);

    uint64_t reported = 0;
    uint64_t moduleOwned = 0;
    uint64_t unowned = 0;
    for (const auto *source : ordered)
    {
        if (!CheckCollection(ctx, budget))
        {
            break;
        }
        ++budget.Report.Collected.Visited;
        const auto prefix = reader.Read(kncore::AddressSpace::Virtual, source->Base, 2);
        ++budget.Report.Collected.Read;
        if (!kncore::ExactBytes(prefix, 2) || prefix.Bytes[0] != 'M' || prefix.Bytes[1] != 'Z')
        {
            continue;
        }
        kncore::MapperImageFacts facts;
        facts.Base = source->Base;
        facts.Size = source->Size;
        facts.PoolTag = source->PoolTag;
        facts.NonPaged = source->NonPaged;
        facts.DriverObjectInventoryVerified = driverNamespaceVerified;
        facts.DriverObjectInventoryNote = driverNamespaceNote;
        if (source->FromPool)
        {
            facts.Sources.push_back(L"BigPoolAllocation");
        }
        if (source->FromDriverObject)
        {
            facts.Sources.push_back(L"DriverObjectStart");
        }
        if (source->FromSweep)
        {
            facts.Sources.push_back(source->SweepSource.empty() ? L"PageSweep" : source->SweepSource);
        }

        const auto owner = owners.Find(source->Base, budget.Report.Stamp);
        if (owner.Image)
        {
            facts.InLoadedModuleList = true;
            facts.ModuleOwner = owner.Image->Name;
            facts.OwnsModuleBase = owner.Rva == 0;
            facts.Sources.push_back(L"LoadedModuleList");
            if (facts.OwnsModuleBase)
            {
                // A module's own start is the normal case; count it and keep the
                // table focused on ranges no module claims.
                ++moduleOwned;
                continue;
            }
        }
        else
        {
            // The image is absent from the module inventory that was read. That only
            // supports "no loaded module owns the range" when the inventory itself was
            // complete, so the observation is carried into the row instead of being
            // assumed.
            facts.ModuleInventoryVerified =
                moduleInventoryUsable && owner.State == kncore::OwnershipState::OutsideCollectedImages;
            facts.ModuleInventoryNote = owner.Reason;
        }

        // The containing range bounds the header read only when that range was read.
        const uint64_t window = source->Size == 0 ? 4096 : std::min<uint64_t>(source->Size, 65536);
        const auto headerBytes = reader.Read(kncore::AddressSpace::Virtual, source->Base, static_cast<size_t>(window));
        ++budget.Report.Collected.Read;
        kncore::PeImage image;
        if (!kncore::ExactBytes(headerBytes, static_cast<size_t>(window)))
        {
            facts.PeMessage = L"header window unreadable";
        }
        else
        {
            const auto parsed = kncore::ParsePeHeaders(headerBytes.Bytes, &image);
            if (!parsed)
            {
                facts.PeMessage = parsed.Error.empty() ? L"PE headers invalid" : parsed.Error;
            }
            else if (source->Size != 0 && !kncore::Contains(source->Size, 0, image.ImageSize))
            {
                facts.PeMessage = L"declared image size exceeds the containing range";
            }
            else
            {
                const auto verified = kncore::ReadMappedPeHeaders(reader, source->Base, image.ImageSize);
                if (verified.State != kncore::Status::Success)
                {
                    facts.PeMessage = verified.Message.empty() ? L"mapped PE header verification failed" : verified.Message;
                }
                else
                {
                    facts.PeValid = true;
                    facts.ImageSize = verified.Image.ImageSize;
                    facts.TimeDateStamp = verified.Image.File.TimeDateStamp;
                    facts.Machine = verified.Image.File.Machine;
                    facts.Sources.push_back(L"MappedPeHeaders");
                    MappedImageBytes bytes(reader, source->Base, facts.ImageSize);
                    const auto codeView = ReadMappedCodeView(bytes, verified.Image);
                    if (!codeView.PdbPath.empty() || !codeView.Identity.empty())
                    {
                        facts.PdbPath = codeView.PdbPath;
                        facts.PdbIdentity = codeView.Identity;
                        facts.Sources.push_back(L"CodeViewRsds");
                    }
                    if (facts.TimeDateStamp != 0)
                    {
                        for (const auto &module : modules)
                        {
                            if (module.Timestamp == facts.TimeDateStamp && module.Size == facts.ImageSize)
                            {
                                facts.MatchedModule = module.ImageName.empty() ? module.ModuleName : module.ImageName;
                                facts.Sources.push_back(L"ModuleBuildMatch");
                                break;
                            }
                        }
                    }
                }
            }
        }

        ApplyHistoryMatches(history, &facts);

        for (const auto &driver : drivers)
        {
            if (!kncore::MapperDriverStartLinks(facts.Base, facts.Size, driver.Start))
            {
                continue;
            }
            facts.DriverObjectLinked = true;
            facts.DriverObject = driver.Object;
            facts.DriverObjectName = driver.Name;
            facts.DriverStartExact = driver.Start == facts.Base;
            if (facts.DriverStartExact)
            {
                break;
            }
        }
        if (facts.DriverObjectLinked)
        {
            facts.Sources.push_back(L"DriverObjectLinkage");
        }

        // The image's own size bounds the permission walk when the containing range is
        // unknown, so the reported permissions still come from the verified image.
        const uint64_t permissionRange = facts.Size != 0 ? facts.Size : facts.ImageSize;
        if (dtbKnown && permissionRange != 0)
        {
            const uint64_t pages = std::min<uint64_t>((permissionRange + 4095) / 4096, 16);
            uint64_t inspected = 0;
            bool first = true;
            bool writable = true;
            bool executable = false;
            for (uint64_t page = 0; page < pages; ++page)
            {
                if (!CheckCollection(ctx, budget))
                {
                    break;
                }
                knengine::PageWalkResult walk;
                const uint64_t va = (facts.Base & ~uint64_t(4095)) + page * 4096;
                if (!knengine::WalkPageTables(ctx.Session, architecture, va, dtb, &walk) || !walk.Ok)
                {
                    continue;
                }
                ++inspected;
                if (first)
                {
                    facts.PageWritable = walk.EffectiveWritable;
                    facts.PageExecutable = walk.EffectiveExecutable;
                    first = false;
                }
                writable = writable && walk.EffectiveWritable;
                executable = executable || walk.EffectiveExecutable;
            }
            if (inspected != 0)
            {
                facts.PageRangeClassified = inspected == pages;
                facts.PageWritable = facts.PageRangeClassified ? std::optional<bool>(writable) : facts.PageWritable;
                facts.PageExecutable = facts.PageRangeClassified ? std::optional<bool>(executable) : facts.PageExecutable;
                facts.Sources.push_back(L"PageTableWalk");
                if (inspected != pages)
                {
                    ++budget.Report.Collected.Unknown;
                }
            }
            else
            {
                ++budget.Report.Collected.Unknown;
            }
        }

        const auto verdict = kncore::ClassifyMapperImage(facts);
        ++unowned;
        budget.Report.Rows.Push(MapperImageRow(facts, verdict));
        if (reported < 256)
        {
            ctx.Out.AddLine(kncore::MapperImageText(facts, verdict));
        }
        ++reported;
    }

    ctx.Out.AddLine(L"[mapper] candidates=" + std::to_wstring(candidates.size()) + L" sweepSlots=" + std::to_wstring(sweepSlots) +
                    L" unowned=" + std::to_wstring(unowned) +
                    L" moduleOwnedSkipped=" + std::to_wstring(moduleOwned) + L" driverObjects=" + std::to_wstring(drivers.size()) +
                    L" driverStartsOwned=" + std::to_wstring(driverStartsOwned) + L" historyRecords=" +
                    std::to_wstring(history.size()) + L" modules=" + std::to_wstring(modules.size()) +
                    (moduleInventoryUsable ? L"" : L" (module inventory unusable)"));
    budget.Report.Limitations.Push(knjson::Value(
        L"Candidates are big-pool allocations whose first bytes are MZ, the interior pages of a big-pool allocation, "
        L"driver-object DriverStart ranges, the pages a loaded module does not own next to each module range, and the ranges "
        L"retained unload records describe. None of them is a verdict of maliciousness: an unowned image can be an unloaded "
        L"driver's leftover pages or a legitimate allocation. A history match is a cross-reference against a retained record, "
        L"so a missing match does not establish that history was erased. Page permissions come from the current CR3 and are "
        L"non-atomic with the rest of the collection. An image without a debug directory has no PDB identity to report. "
        L"Module ownership is judged against the debugger's module list and is reported as unverified when that list does "
        L"not describe the target's own driver images, because a list that owns none of them cannot support the claim "
        L"that nothing owns a range."));
    FinishCollection(ctx, budget);
}
} // namespace kncmd
