#pragma once

#include "ArtifactWriter.h"

namespace knutil
{
class JsonlWriter
{
  public:
    bool Open(const std::wstring &path);
    bool WriteLine(const std::wstring &jsonText);
    bool Commit(bool collectionComplete = true);
    bool IsOpen() const;
    unsigned long Written() const;

  private:
    ArtifactWriter writer_;
    unsigned long written_ = 0;
    bool failed_ = false;
};
} // namespace knutil
