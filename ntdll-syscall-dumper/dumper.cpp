#include <windows.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <optional>
#include <string>
#include <cstdint>

using ByteOpt = std::optional<uint8_t>;

bool match_pattern(const uint8_t* data, const std::vector<ByteOpt>& pattern)
{
    for (size_t i = 0; i < pattern.size(); i++)
    {
        if (pattern[i].has_value() && data[i] != pattern[i].value())
            return false;
    }
    return true;
}

bool is_syscall_stub(const void* func)
{
    static std::vector<ByteOpt> sig =
    {
        0x4C,0x8B,0xD1,0xB8,
        std::nullopt,std::nullopt,std::nullopt,std::nullopt,
        0xF6,std::nullopt,std::nullopt,std::nullopt,
        std::nullopt,std::nullopt,std::nullopt,
        0x01,0x75,std::nullopt,0x0F,0x05
    };

    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(func);
    return match_pattern(bytes, sig);
}

HMODULE load_ntdll()
{
    return LoadLibraryExA(
        "C:\\Windows\\System32\\ntdll.dll",
        nullptr,
        LOAD_LIBRARY_AS_DATAFILE
    );
}

bool validate_headers(const uint8_t* base)
{
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;

    return true;
}

void print_header()
{
    std::cout << "\nSyscall dump from ntdll.dll\n\n";

    std::cout
        << std::left
        << std::setw(5) << "Idx"
        << std::setw(7) << "SysID"
        << std::setw(10) << "RVA(hex)"
        << std::setw(10) << "RVA(dec)"
        << std::setw(20) << "Address(hex)"
        << std::setw(20) << "Address(dec)"
        << "Name"
        << "\n";

    std::cout << std::string(75, '-') << "\n";
}

void dump_syscalls(const uint8_t* base, const IMAGE_EXPORT_DIRECTORY* exp)
{
    auto functions = reinterpret_cast<const uint32_t*>(base + exp->AddressOfFunctions);
    auto names = reinterpret_cast<const uint32_t*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<const uint16_t*>(base + exp->AddressOfNameOrdinals);

    size_t total = 0;

    print_header();

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        uint16_t ord = ordinals[i];
        uint32_t rva = functions[ord];

        const uint8_t* func = base + rva;

        if (!is_syscall_stub(func))
            continue;

        const char* name = reinterpret_cast<const char*>(base + names[i]);

        if (strncmp(name, "Nt", 2) != 0)
            continue;

        uintptr_t data = *reinterpret_cast<const uintptr_t*>(func);
        uint32_t syscall_id = (data >> 32) & 0xFFF;

        uintptr_t address = reinterpret_cast<uintptr_t>(func);

        std::cout
            << std::left
            << std::setw(5) << std::dec << i
            << std::setw(7) << syscall_id
            << "0x" << std::setw(8) << std::hex << rva
            << std::setw(10) << std::dec << rva
            << "0x" << std::setw(16) << std::hex << address
            << std::setw(20) << std::dec << address
            << name
            << "\n";

        total++;
    }

    std::cout << "\nTotal syscalls found: " << total << "\n";
}

int main()
{
    HMODULE mod = load_ntdll();

    if (!mod || mod == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to load ntdll.dll\n";
        return 1;
    }

    const uint8_t* base = reinterpret_cast<const uint8_t*>(mod);

    if (!validate_headers(base))
    {
        std::cerr << "Invalid PE headers\n";
        return 1;
    }

    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

    auto exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );

    dump_syscalls(base, exp);

    return 0;
}