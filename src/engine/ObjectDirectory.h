#pragma once

// Object Manager namespace walker: resolves named objects under a root
// directory (e.g. \Driver) by walking ObpRootDirectoryObject hash buckets.
// Candidate bodies are validated by the caller, so no object-header name
// decoding is required.

#include <functional>
#include <map>
#include <string>

#include "EngineCore.h"
#include "LayoutResolver.h"
#include "../core/Walker.h"

namespace knengine
{
// Visits every candidate object BODY under the given root path segment
// (the directory object itself is resolved by name, e.g. L"Driver").
// Return false from the callback to stop the walk early.
typedef std::function<bool(ULONG64 objectBody)> DirectoryVisitor;

// Named variant: also provides the object's directory entry name, so
// callers can corroborate objects whose type index cannot be verified
// (e.g. an untyped ObTypeIndexTable) by their own name field.
typedef std::function<bool(ULONG64 objectBody, const std::wstring &entryName)> NamedDirectoryVisitor;

class ObjectDirectoryWalker
{
  public:
    explicit ObjectDirectoryWalker(DbgSession &session);

    // Resolves nt!ObpRootDirectoryObject lazily; false when unavailable.
    bool Initialize();

    // Enumerates bodies of all objects directly inside the named
    // sub-directory (one level). Bounded and cycle-guarded.
    bool VisitDirectory(const wchar_t *directoryName, const DirectoryVisitor &visitor, std::wstring *error);

    // Same walk, providing each entry's directory name to the visitor.
    bool VisitDirectoryNamed(const wchar_t *directoryName, const NamedDirectoryVisitor &visitor, std::wstring *error);

    // Recursively walks the whole namespace from the root. The visitor
    // is invoked for every non-directory object with its decoded type
    // index; sub-directories are descended up to maxDepth levels.
    typedef std::function<bool(ULONG64 body, unsigned typeIndex, int depth, const std::wstring &path)> NamespaceVisitor;

    bool VisitNamespace(const NamespaceVisitor &visitor, int maxDepth, std::wstring *error);

    // Resolves an object-manager type index (e.g. "Directory",
    // "ALPC Port") through ObTypeIndexTable. Cached per name.
    // Returns false when the name is absent; index becomes 0xFFFFFFFF.
    bool ResolveTypeIndex(const wchar_t *typeName, unsigned *index);
    bool ObjectTypeIndex(ULONG64 body, unsigned *index);
    const kncore::Result &Report() const;

  private:
    unsigned DecodeTypeIndex(ULONG64 headerAddress);
    ULONG BucketCount();

    bool ReadU64(ULONG64 address, ULONG64 *value);
    bool ReadUnicode(ULONG64 address, std::wstring *text);
    bool ReadName(ULONG64 body, ULONG64 parent, std::wstring *text);
    bool Entries(ULONG64 directory, kncore::WalkBudget &budget, const DirectoryVisitor &visitor);
    bool EntriesNamed(ULONG64 directory, kncore::WalkBudget &budget, const NamedDirectoryVisitor &visitor);
    void Finish(const kncore::WalkBudget &budget, std::wstring *error);

    DbgSession &session_;
    LayoutResolver layout_;
    ULONG64 rootDirectory_;
    bool initialized_;
    std::map<std::wstring, unsigned> typeIndexCache_;
    kncore::TargetArchitecture architecture_;
    kncore::Result report_;
    kncore::SessionStamp stamp_;
};
} // namespace knengine
