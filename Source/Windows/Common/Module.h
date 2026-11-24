// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <FEXCore/fextl/string.h>
#include <winternl.h>

namespace FEX::Windows {
namespace detail {
// RtlUnicodeStringToAnsiString(..., TRUE) allocates the destination string from the process
// heap. That call sits on the image-map path (NotifyMapViewOfSection -> HandleImageMap ->
// GetSectionFilePath), which runs while FEX holds ThreadCreationMutex. A process-heap
// allocation there commits new pages, which re-enters FEX's memory notifications and takes
// ThreadCreationMutex again -- the reverse of the order used by another thread that holds
// the process-heap lock and faults in a FEX allocation (NotifyMemoryAlloc/Protect). That is
// an AB-BA deadlock, and it hung the very first mapped image. Convert into a stack buffer
// instead (AllocateDestinationString = FALSE) so the locked path never touches the heap.
inline fextl::string ConvertToAnsi(const UNICODE_STRING& String) {
  if (!String.Buffer || !String.Length) {
    return {};
  }

  std::array<char, PATH_MAX * 4> Buffer;
  STRING Ansi {
    .Length = 0,
    .MaximumLength = static_cast<USHORT>(Buffer.size()),
    .Buffer = Buffer.data(),
  };

  if (RtlUnicodeStringToAnsiString(&Ansi, &String, FALSE)) {
    return {};
  }

  return fextl::string(Ansi.Buffer, Ansi.Length);
}
} // namespace detail

inline fextl::string GetExecutableFilePath() {
  std::array<WCHAR, PATH_MAX> Buf;
  UNICODE_STRING PathW {.Length = 0, .MaximumLength = Buf.size() * sizeof(WCHAR), .Buffer = Buf.data()};

  if (LdrGetDllFullName(nullptr, &PathW)) {
    return {};
  }

  return detail::ConvertToAnsi(PathW);
}

inline fextl::string GetSectionFilePath(uint64_t Address) {
  struct {
    MEMORY_SECTION_NAME Info;
    std::array<WCHAR, PATH_MAX> PathW;
  } Buffer;

  if (NtQueryVirtualMemory(NtCurrentProcess(), reinterpret_cast<void*>(Address), MemoryMappedFilenameInformation, &Buffer, sizeof(Buffer), NULL)) {
    return {};
  }

  return detail::ConvertToAnsi(Buffer.Info.SectionFileName);
}

inline std::string_view BaseName(std::string_view Path) {
  return Path.substr(Path.find_last_of('\\') + 1);
}
} // namespace FEX::Windows
