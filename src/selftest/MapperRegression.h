#pragma once

#include "CollectorRegression.h"
#include "../core/MapperDetect.h"

namespace knself
{
// The mapper classification decides whether an image is reported as a hidden
// driver at all, so the cases below are the ones where a defect becomes a real
// false positive or a missed detection: a module's own base, an image inside
// another module's range, unverified headers, and the driver-object linkage.
template <typename Check> void RunMapperRegression(Check check)
{
    using namespace kncore;
    MapperImageFacts facts;
    facts.Base = 0xffffbd816181c000ULL;
    facts.Size = 0x2000;
    facts.PeValid = true;
    facts.ModuleInventoryVerified = true;
    facts.ImageSize = 0x1800;
    facts.TimeDateStamp = 0x5f2a1b3c;
    facts.Machine = 0x8664;
    facts.PoolTag = L"Mapp";
    facts.NonPaged = true;
    facts.Sources.push_back(L"BigPoolAllocation");
    facts.Sources.push_back(L"MappedPeHeaders");
    facts.DriverObjectInventoryVerified = true;

    check(ClassifyMapperImage(facts).Classification == L"ManualMappedDriverUnlinked",
          "mapper.unowned-pe-image-is-a-manual-mapping");
    check(ClassifyMapperImage(facts).Confidence == L"Medium",
          "mapper.unlinked-image-does-not-claim-high-confidence");

    auto linked = facts;
    linked.DriverObjectLinked = true;
    linked.DriverObject = 0xffffbd8161900000ULL;
    linked.DriverObjectName = L"MapperTestDriver";
    linked.DriverStartExact = true;
    const auto linkedVerdict = ClassifyMapperImage(linked);
    check(linkedVerdict.Classification == L"ManualMappedDriverLinked" && linkedVerdict.Confidence == L"High",
          "mapper.driver-object-linkage-raises-the-classification");
    check(linkedVerdict.Reason.find(L"MapperTestDriver") != std::wstring::npos,
          "mapper.verdict-reason-names-the-linked-driver-object");

    auto owned = facts;
    owned.InLoadedModuleList = true;
    owned.OwnsModuleBase = true;
    owned.ModuleOwner = L"nt";
    check(ClassifyMapperImage(owned).Classification == L"LoadedModuleImage",
          "mapper.module-start-is-not-reported-as-a-mapping");

    auto inside = facts;
    inside.InLoadedModuleList = true;
    inside.ModuleOwner = L"nt";
    check(ClassifyMapperImage(inside).Classification == L"MappedInsideModuleRange",
          "mapper.image-inside-a-module-range-is-flagged");

    auto unverified = facts;
    unverified.PeValid = false;
    unverified.PeMessage = L"invalid PE signature or section count";
    const auto unverifiedVerdict = ClassifyMapperImage(unverified);
    check(unverifiedVerdict.Classification == L"ManualMappedHeadersUnverified" &&
              unverifiedVerdict.Reason.find(L"invalid PE signature") != std::wstring::npos,
          "mapper.invalid-headers-are-not-reported-as-a-valid-image");

    // An inventory that was not read completely cannot support the claim that no
    // module owns the range, so this is the case where the verdict has to stay
    // unverified instead of reporting a mapping nobody confirmed.
    auto incompleteInventory = facts;
    incompleteInventory.ModuleInventoryVerified = false;
    incompleteInventory.ModuleInventoryNote = L"module list enumeration failed";
    const auto incompleteVerdict = ClassifyMapperImage(incompleteInventory);
    check(incompleteVerdict.Classification == L"ManualMappedSuspectModuleOwnershipUnverified" &&
              incompleteVerdict.Reason.find(L"module list enumeration failed") != std::wstring::npos &&
              MapperImageText(incompleteInventory, incompleteVerdict).find(L"module=unverified") != std::wstring::npos,
          "mapper.incomplete-module-inventory-keeps-ownership-unverified");

    // The loaded-module inventory is what turns "no collected image contains this
    // address" into "no loaded module owns the range". A list that is empty or that
    // owns none of the target's driver images cannot support that claim - observed
    // live as a session whose module list had not been reloaded and every loaded
    // driver being reported as a mapping.
    check(!MapperModuleInventoryUsable(true, true, 129, 0), "mapper.empty-module-inventory-is-not-usable");
    check(!MapperModuleInventoryUsable(false, false, 129, 129), "mapper.incomplete-module-inventory-is-not-usable");
    check(!MapperModuleInventoryUsable(true, false, 129, 0), "mapper.module-inventory-that-owns-no-driver-is-not-usable");
    check(MapperModuleInventoryUsable(true, false, 129, 129), "mapper.module-inventory-that-owns-drivers-is-usable");
    check(MapperModuleInventoryUsable(true, false, 0, 0), "mapper.inventory-without-driver-objects-stays-usable");

    check(MapperImageIdentity(facts) == L"pool tag Mapp", "mapper.identity-falls-back-to-the-pool-tag");
    auto withPdb = facts;
    withPdb.PdbPath = L"symbols/hidden.sys.pdb";
    check(MapperImageIdentity(withPdb) == L"symbols/hidden.sys.pdb", "mapper.identity-prefers-the-pdb-path");
    auto withModule = facts;
    withModule.MatchedModule = L"hidden.sys";
    check(MapperImageIdentity(withModule).find(L"hidden.sys") == 0, "mapper.identity-uses-a-build-matching-module");

    check(MapperPermissionText(facts) == L"unknown", "mapper.unknown-permissions-are-not-assumed");
    auto writable = facts;
    writable.PageWritable = true;
    writable.PageExecutable = false;
    writable.PageRangeClassified = true;
    check(MapperPermissionText(writable) == L"W-", "mapper.permission-text-reports-the-observed-bits");
    writable.PageRangeClassified = false;
    check(MapperPermissionText(writable) == L"W- (partial range)", "mapper.partial-page-coverage-is-marked");

    const auto text = MapperImageText(facts, ClassifyMapperImage(facts));
    check(text.find(L"base=0xFFFFBD816181C000") != std::wstring::npos && text.find(L"size=8192") != std::wstring::npos &&
              text.find(L"pool tag Mapp") != std::wstring::npos && text.find(L"module=none") != std::wstring::npos &&
              text.find(L"driver=none") != std::wstring::npos && text.find(L"pages=unknown") != std::wstring::npos,
          "mapper.text-line-carries-base-size-identity-module-driver-and-pages");
    check(MapperHex(0xFFFFBD816181C000ULL) == L"0xFFFFBD816181C000", "mapper.hex-address-text");

    // The history cross-reference decides whether an unowned image is reported as
    // a hidden driver or as something the loader's own records already explain,
    // so these are the cases where a defect becomes a false positive or a missed
    // detection.
    check(MapperHistoryText(facts) == L"none", "mapper.image-without-a-history-match-says-none");

    auto residue = facts;
    residue.UnloadedDriverRangeMatch = true;
    residue.UnloadedDriverName = L"hidden.sys";
    const auto residueVerdict = ClassifyMapperImage(residue);
    check(residueVerdict.Classification == L"UnloadedDriverResidue" && residueVerdict.Confidence == L"Medium",
          "mapper.unload-record-range-explains-an-unowned-image");
    check(residueVerdict.Reason.find(L"hidden.sys") != std::wstring::npos,
          "mapper.residue-verdict-names-the-retained-unload-record");

    auto linkedResidue = residue;
    linkedResidue.DriverObjectLinked = true;
    linkedResidue.DriverObject = 0xffffbd8161900000ULL;
    check(ClassifyMapperImage(linkedResidue).Classification == L"ManualMappedDriverLinked",
          "mapper.live-driver-object-outranks-an-unload-record");

    auto database = facts;
    database.DriverDatabaseMatch = true;
    database.DriverDatabaseName = L"hidden.sys";
    const auto databaseVerdict = ClassifyMapperImage(database);
    check(databaseVerdict.Classification == L"ManualMappedDriverUnlinked" && databaseVerdict.Confidence == L"High",
          "mapper.driver-database-build-match-raises-an-unlinked-image");
    check(databaseVerdict.Reason.find(L"hidden.sys") != std::wstring::npos,
          "mapper.database-verdict-names-the-matched-entry");

    auto ciOnly = facts;
    ciOnly.CiCacheMatch = true;
    ciOnly.CiCacheName = L"hidden.sys";
    const auto ciVerdict = ClassifyMapperImage(ciOnly);
    check(ciVerdict.Classification == L"ManualMappedDriverUnlinked" && ciVerdict.Confidence == L"Medium",
          "mapper.ci-cache-name-match-does-not-overstate-confidence");
    check(ciVerdict.Reason.find(L"hidden.sys") != std::wstring::npos, "mapper.ci-verdict-names-the-cache-entry");

    auto named = facts;
    named.PdbPath = L"symbols/hidden.sys.pdb";
    named.DriverDatabaseMatch = true;
    named.DriverDatabaseName = L"hidden.sys";
    check(MapperMatchName(named) == L"hidden.sys", "mapper.match-name-reduces-a-pdb-path-to-its-stem");
    check(MapperImageIdentity(named) == L"symbols/hidden.sys.pdb", "mapper.identity-keeps-the-pdb-path");
    auto historyOnly = facts;
    historyOnly.CiCacheMatch = true;
    historyOnly.CiCacheName = L"hidden.sys";
    check(MapperImageIdentity(historyOnly).find(L"hidden.sys") == 0,
          "mapper.identity-falls-back-to-the-history-name");
    check(MapperHistoryText(named).find(L"piddb(hidden.sys)") != std::wstring::npos,
          "mapper.history-text-names-the-matched-record");
    check(MapperNameEqual(L"hidden.sys", L"HIDDEN.SYS") && !MapperNameEqual(L"hidden.sys", L"other.sys"),
          "mapper.name-comparison-ignores-case-and-rejects-a-different-name");

    // A driver object registered by a manually mapped image commonly carries a
    // DriverStart with no DriverSize, so the linkage must not require a size, and the
    // range a row reports must stay unknown instead of becoming a zero-sized one.
    check(MapperDriverStartLinks(0xffffbd816181c000ULL, 0, 0xffffbd816181c000ULL),
          "mapper.driver-start-without-a-size-still-links-the-image");
    check(!MapperDriverStartLinks(0xffffbd816181c000ULL, 0, 0xffffbd8161811000ULL) &&
              MapperDriverStartLinks(0xffffbd816181c000ULL, 0x2000, 0xffffbd816181d000ULL) &&
              !MapperDriverStartLinks(0xffffbd816181c000ULL, 0x2000, 0xffffbd816181e000ULL) &&
              !MapperDriverStartLinks(0xffffbd816181c000ULL, 0x2000, 0),
          "mapper.driver-start-links-at-the-base-or-inside-a-known-range");
    auto unsized = facts;
    unsized.Size = 0;
    check(MapperImageText(unsized, ClassifyMapperImage(unsized)).find(L"size=unknown") != std::wstring::npos,
          "mapper.unknown-containing-range-is-not-reported-as-zero");

    // A row's driver-object linkage is an absence claim about the target's \Driver
    // namespace, so a namespace that was not read completely must leave the linkage
    // unverified instead of reporting that no driver object points into the image.
    auto unreadDriverNamespace = facts;
    unreadDriverNamespace.DriverObjectInventoryVerified = false;
    unreadDriverNamespace.DriverObjectInventoryNote = L"Driver object namespace walk did not complete";
    const auto unreadVerdict = ClassifyMapperImage(unreadDriverNamespace);
    check(unreadVerdict.Reason.find(L"driver-object linkage could not be established") != std::wstring::npos &&
              unreadVerdict.Reason.find(L"Driver object namespace walk did not complete") != std::wstring::npos &&
              MapperImageText(unreadDriverNamespace, unreadVerdict).find(L"driver=unverified") != std::wstring::npos,
          "mapper.unread-driver-namespace-keeps-the-linkage-unverified");
    check(ClassifyMapperImage(facts).Reason.find(L"no driver object's DriverStart lies inside it") != std::wstring::npos &&
              MapperImageText(facts, ClassifyMapperImage(facts)).find(L"driver=none") != std::wstring::npos,
          "mapper.read-driver-namespace-supports-the-absence-claim");

    // The reporting gate decides whether a candidate becomes a detection row, so these are
    // the inputs that live collection turned into false positives: pages of mapped firmware
    // images that no record named, non-executable copies of loaded drivers, and PE-shaped
    // bytes whose image did not verify.
    check(MapperRowDecision(facts) == MapperRowDrop::None, "mapper.record-named-executable-image-is-reported");

    auto sweepPage = facts;
    sweepPage.SweepOnly = true;
    check(MapperRowDecision(sweepPage) == MapperRowDrop::SweepPageNoRecord,
          "mapper.sweep-page-without-a-record-is-not-a-detection-row");
    auto sweepResidue = sweepPage;
    sweepResidue.UnloadedDriverRangeMatch = true;
    check(MapperRowDecision(sweepResidue) == MapperRowDrop::None,
          "mapper.record-that-names-a-sweep-page-keeps-it-reportable");

    auto copy = facts;
    copy.PageRangeClassified = true;
    copy.PageRangeComplete = true;
    copy.PageExecutable = false;
    check(MapperRowDecision(copy) == MapperRowDrop::ImageCopyNotExecutable,
          "mapper.non-executable-image-is-not-a-detection-row");
    auto partialWalk = copy;
    partialWalk.PageRangeComplete = false;
    check(MapperRowDecision(partialWalk) == MapperRowDrop::None,
          "mapper.partial-page-coverage-does-not-invent-a-non-executable-image");

    auto mzOnly = facts;
    mzOnly.PeValid = false;
    mzOnly.PeMessage = L"declared image size exceeds the containing range";
    check(MapperRowDecision(mzOnly) == MapperRowDrop::MzPrefixOnly,
          "mapper.unverified-pe-headers-are-not-a-detection-row");
}
} // namespace knself
