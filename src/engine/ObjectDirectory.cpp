#include "ObjectDirectory.h"
#include "PageWalk.h"
#include "../core/ObjectRead.h"
#include "../core/NamespaceWalk.h"
#include "../util/Log.h"
#include <dbgeng.h>
#include <set>

namespace knengine
{
ObjectDirectoryWalker::ObjectDirectoryWalker(DbgSession &session) : ObjectDirectoryWalker(session, session)
{
}

ObjectDirectoryWalker::ObjectDirectoryWalker(DbgSession &session, kncore::TargetReader &reader)
    : session_(session), reader_(reader), layout_(session, reader), rootDirectory_(0), initialized_(false)
{
}

bool ObjectDirectoryWalker::ReadU64(ULONG64 address, ULONG64 *value)
{
    return reader_.ReadExact(kncore::AddressSpace::Virtual, address, value);
}

bool ObjectDirectoryWalker::Initialize()
{
    const auto stamp = session_.RefreshStamp();
    if (initialized_ && stamp_ == stamp)
    {
        return true;
    }
    initialized_ = false;
    typeIndexCache_.clear();
    SessionStatus status = {};
    session_.QueryStatus(&status);
    ULONG64 cr4 = 0;
    const auto root = layout_.Address(L"nt", L"ObpRootDirectoryObject");
    if (!status.KernelMode || status.Architecture != IMAGE_FILE_MACHINE_AMD64 || !session_.ReadRegisterHex(L"cr4", &cr4) || !root ||
        !ReadU64(*root, &rootDirectory_))
    {
        report_.State = kncore::Status::Unavailable;
        report_.Error.Message = L"Object root or target architecture unavailable";
        return false;
    }
    architecture_ = {IMAGE_FILE_MACHINE_AMD64, 8, Cr4HasLa57(cr4) ? 57u : 48u, {}};
    initialized_ = architecture_.KernelPointer(rootDirectory_);
    stamp_ = session_.RefreshStamp();
    return initialized_;
}

bool ObjectDirectoryWalker::ReadUnicode(ULONG64 address, std::wstring *text)
{
    return kncore::ReadUnicodeValue(reader_, address, layout_.Field(L"nt", L"_UNICODE_STRING", L"Length"),
                                    layout_.Field(L"nt", L"_UNICODE_STRING", L"MaximumLength"),
                                    layout_.Field(L"nt", L"_UNICODE_STRING", L"Buffer"), architecture_, text);
}

bool ObjectDirectoryWalker::ReadName(ULONG64 body, ULONG64 parent, std::wstring *text)
{
    const auto headerBody = layout_.Field(L"nt", L"_OBJECT_HEADER", L"Body");
    const auto name = layout_.Field(L"nt", L"_OBJECT_HEADER_NAME_INFO", L"Name");
    const auto directory = layout_.Field(L"nt", L"_OBJECT_HEADER_NAME_INFO", L"Directory");
    ULONG headerSize = 0;
    ULONG nameInfoSize = 0;
    if (!headerBody || !name || !directory || directory->Size != 8 || body < headerBody->Offset ||
        !layout_.TypeSize(L"_OBJECT_HEADER", &headerSize) || !layout_.TypeSize(L"_OBJECT_HEADER_NAME_INFO", &nameInfoSize) ||
        !kncore::ValidRange(body - headerBody->Offset, headerSize))
    {
        return false;
    }
    const auto header = body - headerBody->Offset;
    unsigned char offset = 0;
    const auto legacy = layout_.Field(L"nt", L"_OBJECT_HEADER", L"NameInfoOffset");
    if (legacy && legacy->Size == 1)
    {
        if (!reader_.ReadExact(kncore::AddressSpace::Virtual, header + legacy->Offset, &offset))
        {
            return false;
        }
    }
    else
    {
        const auto info = layout_.Field(L"nt", L"_OBJECT_HEADER", L"InfoMask");
        unsigned char mask = 0;
        const auto table = layout_.Address(L"nt", L"ObpInfoMaskToOffset");
        // The mask indexes a UCHAR table; only the low bits are consulted and
        // the bounded read below keeps untyped public storage (Insider PDBs
        // ship no array shape) as safe as the shaped form. The decoded
        // offset must still hold a plausible name-info extent above.
        if (!info || info->Size != 1 || !reader_.ReadExact(kncore::AddressSpace::Virtual, header + info->Offset, &mask) ||
            (mask & 2) == 0 || !table || !kncore::ValidRange(*table, 4) ||
            !reader_.ReadExact(kncore::AddressSpace::Virtual, *table + (mask & 3), &offset))
        {
            return false;
        }
    }
    ULONG64 observedParent = 0;
    return offset >= nameInfoSize && offset != 0 && header >= offset && kncore::ValidRange(header - offset, nameInfoSize) &&
           ReadU64(header - offset + directory->Offset, &observedParent) && observedParent == parent &&
           ReadUnicode(header - offset + name->Offset, text);
}

ULONG ObjectDirectoryWalker::BucketCount()
{
    const auto buckets = layout_.Field(L"nt", L"_OBJECT_DIRECTORY", L"HashBuckets");
    if (!buckets || buckets->Kind != kncore::FieldKind::Array || buckets->ElementSize != 8u || !buckets->ArrayCount ||
        *buckets->ArrayCount > 512)
    {
        return 0;
    }
    return *buckets->ArrayCount;
}

bool ObjectDirectoryWalker::Entries(ULONG64 directory, kncore::WalkBudget &budget, const DirectoryVisitor &visitor)
{
    const auto buckets = layout_.Field(L"nt", L"_OBJECT_DIRECTORY", L"HashBuckets");
    const auto next = layout_.Field(L"nt", L"_OBJECT_DIRECTORY_ENTRY", L"ChainLink");
    const auto object = layout_.Field(L"nt", L"_OBJECT_DIRECTORY_ENTRY", L"Object");
    const ULONG count = BucketCount();
    if (!buckets || !next || !object || count == 0 || next->Size != 8 || object->Size != 8)
    {
        return budget.Stop(kncore::Status::Unavailable, L"VerifiedDirectoryArrayOrEntryLayoutUnavailable");
    }
    for (ULONG i = 0; i < count && !budget.Stopped; ++i)
    {
        ULONG64 first = 0;
        const uint64_t offset = static_cast<uint64_t>(buckets->Offset) + i * 8;
        if (!kncore::ValidRange(directory, offset + 8) || !ReadU64(directory + offset, &first))
        {
            ++budget.Report.Collected.Unreadable;
            return budget.Stop(kncore::Status::Partial, L"UnreadableDirectoryBucket");
        }
        // Begin once after root/type/layout discovery and the first KD read.
        // Child directories and later buckets share the same deadline.
        budget.StartTraversal();
        kncore::WalkChain(reader_, first, 0, next->Offset, architecture_, budget,
                          [&](uint64_t entry)
                          {
                              ULONG64 body = 0;
                              if (!kncore::ValidRange(entry, static_cast<uint64_t>(object->Offset) + 8) ||
                                  !ReadU64(entry + object->Offset, &body) || !architecture_.KernelPointer(body))
                              {
                                  return kncore::VisitDecision::Failed;
                              }
                              return visitor(body) ? kncore::VisitDecision::Continue : kncore::VisitDecision::Stop;
                          });
    }
    return budget.Report.State == kncore::Status::Success;
}

bool ObjectDirectoryWalker::EntriesNamed(ULONG64 directory, kncore::WalkBudget &budget, const NamedDirectoryVisitor &visitor)
{
    return Entries(directory, budget,
                   [&](ULONG64 body)
                   {
                       std::wstring name;
                       const bool hasName = ReadName(body, directory, &name);
                       return visitor(body, hasName ? name : std::wstring());
                   });
}

void ObjectDirectoryWalker::Finish(const kncore::WalkBudget &budget, std::wstring *error)
{
    report_ = budget.Report;
    report_.Stamp = stamp_;
    report_.Source = L"target-memory";
    report_.Consistency = L"BestEffortBoundedWalk";
    if (const auto identity = layout_.Identity(L"nt"))
    {
        report_.LayoutProfile = identity->Key();
    }
    if (session_.RefreshStamp() != stamp_ && report_.State == kncore::Status::Success)
    {
        report_.State = kncore::Status::StaleContext;
        report_.Collected.Complete = false;
    }
    if (error != nullptr)
    {
        *error = report_.State == kncore::Status::Success ? L"" : report_.Collected.StopReason;
    }
}

const kncore::Result &ObjectDirectoryWalker::Report() const
{
    return report_;
}

bool ObjectDirectoryWalker::VisitDirectory(const wchar_t *directoryName, const DirectoryVisitor &visitor, std::wstring *error)
{
    return VisitDirectoryNamed(
        directoryName,
        [&visitor](ULONG64 body, const std::wstring &)
        {
            return visitor(body);
        },
        error);
}

bool ObjectDirectoryWalker::VisitDirectoryNamed(const wchar_t *directoryName, const NamedDirectoryVisitor &visitor,
                                                std::wstring *error)
{
    kncore::WalkBudget budget;
    budget.Cancelled = [&]()
    {
        return session_.Cancelled();
    };
    do
    {
        if (directoryName == nullptr || !visitor || !Initialize())
        {
            budget.Stop(kncore::Status::Unavailable, L"ObjectRootUnavailable");
            break;
        }
        unsigned directoryType = 0;
        const auto headerBody = layout_.Field(L"nt", L"_OBJECT_HEADER", L"Body");
        if (!ResolveTypeIndex(L"Directory", &directoryType) || !headerBody || rootDirectory_ < headerBody->Offset ||
            DecodeTypeIndex(rootDirectory_ - headerBody->Offset) != directoryType)
        {
            budget.Stop(kncore::Status::Unavailable, L"ObjectCookieDecodeNotCorroboratedByRootType");
            break;
        }
        ULONG64 found = 0;
        // Driver records include names and dispatch metadata over remote KD.
        // Keep one bounded deadline across root lookup and the target directory.
        budget.StartTraversal(std::chrono::steady_clock::now(), std::chrono::seconds(60));
        Entries(rootDirectory_, budget,
                [&](ULONG64 body)
                {
                    std::wstring name;
                    if (body >= headerBody->Offset && DecodeTypeIndex(body - headerBody->Offset) == directoryType &&
                        ReadName(body, rootDirectory_, &name) && _wcsicmp(name.c_str(), directoryName) == 0)
                    {
                        found = body;
                        return false;
                    }
                    return true;
                });
        if (found == 0)
        {
            if (!budget.Stopped)
            {
                budget.Stop(kncore::Status::Unavailable, L"DirectoryNotResolvedFromObservedNames");
            }
            break;
        }
        budget.Stopped = false;
        budget.Report.Collected.StopReason = L"TargetDirectoryWalk";
        EntriesNamed(found, budget, visitor);
        budget.Complete();
    } while (false);
    Finish(budget, error);
    return report_.State == kncore::Status::Success;
}

bool ObjectDirectoryWalker::ResolveTypeIndex(const wchar_t *typeName, unsigned *index, const wchar_t *typeSymbol)
{
    if (index == nullptr || typeName == nullptr || !Initialize())
    {
        return false;
    }
    *index = UINT32_MAX;
    if (const auto found = typeIndexCache_.find(typeName); found != typeIndexCache_.end())
    {
        *index = found->second;
        return true;
    }
    const auto name = layout_.Field(L"nt", L"_OBJECT_TYPE", L"Name");
    const auto typeIndex = layout_.Field(L"nt", L"_OBJECT_TYPE", L"Index");
    const auto table = layout_.Address(L"nt", L"ObTypeIndexTable");
    const auto shape = layout_.Symbol(L"nt", L"ObTypeIndexTable");
    unsigned slots = 0;
    if (shape && shape->Kind == kncore::FieldKind::Array && shape->ElementSize == 8u && shape->ArrayCount &&
        *shape->ArrayCount <= 256 && shape->ValidFor(shape->Size))
    {
        slots = *shape->ArrayCount;
    }
    else if (table)
    {
        // Untyped public storage (Insider PDBs): bound the search by the
        // table's own structure. Slot entries remain self-verified below.
        slots = StructurallyBoundedTypeSlotCount(reader_, *table);
    }
    if (!name || !typeIndex || typeIndex->Size != 1 || !table || slots == 0)
    {
        return false;
    }
    const auto matches = [&](unsigned slot, uint64_t object)
    {
        unsigned char indexByte = 0;
        std::wstring text;
        const bool readable = kncore::ValidRange(object,
                                                 std::max<uint64_t>(typeIndex->Offset + 1, static_cast<uint64_t>(name->Offset) + name->Size)) &&
                               reader_.ReadExact(kncore::AddressSpace::Virtual, object + typeIndex->Offset, &indexByte) &&
                               ReadUnicode(object + name->Offset, &text);
        if (!readable)
        {
            return false;
        }
        if (indexByte != slot)
        {
            // Type objects whose recorded Index disagrees with their table
            // slot are refused; keep the mismatch visible for diagnosis.
            knlog::Write(L"ObjectType slot " + std::to_wstring(slot) + L" name=" + text + L" indexByte=" +
                         std::to_wstring(indexByte) + L" (mismatch; refused)");
            return false;
        }
        return _wcsicmp(text.c_str(), typeName) == 0;
    };
    const auto cancelled = [&]()
    {
        return session_.Cancelled();
    };
    std::optional<unsigned> found;
    if (typeSymbol != nullptr && !cancelled())
    {
        const auto reference = layout_.Address(L"nt", typeSymbol);
        if (reference)
        {
            found = kncore::FindReferencedPointerSlot(reader_, *reference, *table, slots, typeIndex, architecture_, matches, cancelled);
        }
    }
    if (!found && !cancelled())
    {
        // Missing or contradictory hints retain the established table search.
        found = kncore::FindSparsePointerSlot(reader_, *table, slots, architecture_, matches, cancelled);
    }
    if (found)
    {
        *index = *found;
        typeIndexCache_[typeName] = *found;
        return true;
    }
    return false;
}

bool ObjectDirectoryWalker::ObjectTypeIndex(ULONG64 body, unsigned *index)
{
    unsigned directoryIndex = UINT32_MAX;
    const auto field = layout_.Field(L"nt", L"_OBJECT_HEADER", L"Body");
    if (index == nullptr || !field || !ResolveTypeIndex(L"Directory", &directoryIndex) || rootDirectory_ < field->Offset ||
        DecodeTypeIndex(rootDirectory_ - field->Offset) != directoryIndex || !architecture_.KernelPointer(body) || body < field->Offset)
    {
        return false;
    }
    *index = DecodeTypeIndex(body - field->Offset);
    return *index != UINT32_MAX;
}

unsigned ObjectDirectoryWalker::DecodeTypeIndex(ULONG64 header)
{
    const auto typeIndex = layout_.Field(L"nt", L"_OBJECT_HEADER", L"TypeIndex");
    unsigned char raw = 0;
    unsigned char cookie = 0;
    const auto cookieAddress = layout_.Address(L"nt", L"ObHeaderCookie");
    if (!typeIndex || typeIndex->Size != 1 || !kncore::ValidRange(header, static_cast<uint64_t>(typeIndex->Offset) + 1) ||
        !reader_.ReadExact(kncore::AddressSpace::Virtual, header + typeIndex->Offset, &raw) || !cookieAddress ||
        !reader_.ReadExact(kncore::AddressSpace::Virtual, *cookieAddress, &cookie))
    {
        return UINT32_MAX;
    }
    return static_cast<unsigned char>(raw ^ cookie ^ (header >> 8));
}

kncore::NamespaceLayout ResolveNamespaceLayout(LayoutResolver &layout)
{
    kncore::NamespaceLayout fields;
    fields.Buckets = layout.Field(L"nt", L"_OBJECT_DIRECTORY", L"HashBuckets");
    fields.Next = layout.Field(L"nt", L"_OBJECT_DIRECTORY_ENTRY", L"ChainLink");
    fields.Object = layout.Field(L"nt", L"_OBJECT_DIRECTORY_ENTRY", L"Object");
    fields.Body = layout.Field(L"nt", L"_OBJECT_HEADER", L"Body");
    fields.Type = layout.Field(L"nt", L"_OBJECT_HEADER", L"TypeIndex");
    fields.Mask = layout.Field(L"nt", L"_OBJECT_HEADER", L"InfoMask");
    fields.Parent = layout.Field(L"nt", L"_OBJECT_HEADER_NAME_INFO", L"Directory");
    const auto name = layout.Field(L"nt", L"_OBJECT_HEADER_NAME_INFO", L"Name");
    fields.Length = kncore::NestedField(name, layout.Field(L"nt", L"_UNICODE_STRING", L"Length"));
    fields.Maximum = kncore::NestedField(name, layout.Field(L"nt", L"_UNICODE_STRING", L"MaximumLength"));
    fields.Buffer = kncore::NestedField(name, layout.Field(L"nt", L"_UNICODE_STRING", L"Buffer"));
    ULONG nameSize = 0;
    layout.TypeSize(L"_OBJECT_HEADER_NAME_INFO", &nameSize);
    fields.NameInfoSize = nameSize;
    return fields;
}

bool ObjectDirectoryWalker::VisitNamespace(const NamespaceVisitor &visitor, unsigned selectedType, int maxDepth, std::wstring *error)
{
    kncore::WalkBudget budget;
    budget.Cancelled = [&]()
    {
        return session_.Cancelled();
    };
    do
    {
        unsigned directoryType = 0;
        if (!visitor || maxDepth < 0 || maxDepth > 32 || !Initialize() || !ResolveTypeIndex(L"Directory", &directoryType))
        {
            budget.Stop(kncore::Status::Unavailable, L"DirectoryTypeUnavailable");
            break;
        }
        const auto cookie = layout_.Address(L"nt", L"ObHeaderCookie");
        const auto offsets = layout_.Address(L"nt", L"ObpInfoMaskToOffset");
        if (!cookie || !offsets || !layout_.VerifyProfile(kncore::KernelLayoutFamily::ObjectTypes) ||
            !layout_.VerifyProfile(kncore::KernelLayoutFamily::ObjectNames))
        {
            budget.Stop(kncore::Status::Unavailable, L"NamespaceDecoderProfileUnavailable");
            break;
        }
        const auto fields = ResolveNamespaceLayout(layout_);
        kncore::NamespaceReadMeter measured(reader_);
        kncore::WalkNamedNamespace(measured, architecture_, fields, rootDirectory_, *cookie, *offsets, directoryType,
                                  selectedType, static_cast<unsigned>(maxDepth), budget, visitor);
        budget.Report.Analysis.Set(L"namespaceTargetReads", knjson::Value(std::to_wstring(measured.Requests)));
        budget.Report.Analysis.Set(L"namespaceRequestedBytes", knjson::Value(std::to_wstring(measured.Bytes)));
    } while (false);
    Finish(budget, error);
    return report_.State == kncore::Status::Success;
}
} // namespace knengine
