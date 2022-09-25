#include "integrity.h"

#include <array>

/// Macro that enables or disables the printing macros from this file.
#define LOG_DATA 1

#if LOG_DATA
#define LOG(...)                                                               \
  std::printf(__VA_ARGS__);                                                    \
  std::printf("\n")
#else
#define LOG
#endif

/// <summary>
/// Example function which will be patched and called to demonstrate this PoC's
/// functionality.
/// </summary>
/// <param name="a">First number to be added</param>
/// <param name="b">Second number to be added</param>
/// <returns>The sum of both numbers.</returns>
int addition(int a, int b) { return a + b; }

/// <summary>
/// Namespace used to store all the integrity checks data.
/// </summary>
namespace IntegrityChecksTable {
DECLARE_FUNCTION_DATA(addition);
} // namespace IntegrityChecksTable

/// <summary>
/// Patches the addition function by changing the page protection to rwx, then
/// patching in assembly equivalent to:
///
/// int addition() { return 1337; }
///
/// Then changes back the code page's protection back to what it was before.
/// </summary>
void patch_addition() {
  LOG("Patching addition...");

  // patch the function now, because we're evil haxxors
  DWORD old;
  VirtualProtect(addition, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &old);

  // movabs rax, 1337 ; dec
  // ret
  std::array<uint8_t, 11> return_1337_shell = {
      0x48, 0xB8, 0x39, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC3};

  // overwrite the addition function to always return 1337
  for (auto i = 0; i < return_1337_shell.size(); i++) {
    reinterpret_cast<uint8_t *>(addition)[i] = return_1337_shell[i];
  }

  VirtualProtect(addition, PAGE_SIZE, old, &old);
}

/// <summary>
/// Code that executes if the addition code has been tampered with.
/// </summary>
void addition_tampered() { LOG("The addition code has been tampered with!"); }

int main() {
  // load data in xorred data buffer containing its code
  LOAD_FUNCTION_DATA(IntegrityChecksTable, addition);
  // check that the data matches the function's actual code
  CHECK_FUNCTION_DATA(IntegrityChecksTable, addition, addition_tampered());

  // run the function
  LOG("Addition result %d", addition(5, 5));

  // patch the function
  patch_addition();

  // the program should now say that the addition function has been tampered
  // with
  CHECK_FUNCTION_DATA(IntegrityChecksTable, addition, addition_tampered());

  // but wait, we can force call it (the function will be healed and called)
  auto result = FORCED_FUNCTION_CALL(IntegrityChecksTable, addition, 5, 5);
  LOG("Healed addition result %d", result);

  // patch it again!
  patch_addition();

  // alternatively, we can have some other code execute if the function has been
  // tampered with (we will still get the results from the tampered function,
  // instead of receiving genuine results from a healed function).
  auto tampered_result = CHECKED_FUNCTION_CALL(IntegrityChecksTable, addition,
                                               addition_tampered(), 5, 5);
  LOG("Tampered addition results %d", tampered_result);
}