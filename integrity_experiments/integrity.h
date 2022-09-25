#pragma once
#include <Windows.h>

#include <iostream>
#include <string>
#include <vector>

/// Size of a memory page.
#define PAGE_SIZE 0x1000

/// Aligns a memory address to the start of its corresponding page (this system
/// saves entire pages into memory, since it's not capable of understanding
/// where a function starts and where a function ends reliably, especially with
/// optimizations enabled).
#define PAGE_ALIGN(address)                                                    \
  (uint8_t *)(reinterpret_cast<uint64_t>(address) -                            \
              (reinterpret_cast<uint64_t>(address) % PAGE_SIZE))

/// Declares the data structure necessary to store a function's memory page.
#define DECLARE_FUNCTION_DATA(name)                                            \
  static uint8_t function_page_data_##name[PAGE_SIZE];

/// Loads a function's code into its corresponding xorred memory page which will
/// be used for integrity checking purposes.
#define LOAD_FUNCTION_DATA(space, name)                                        \
  {                                                                            \
    uint8_t *address_##name = PAGE_ALIGN((uint8_t *)&name);                    \
    for (auto i = 0; i < PAGE_SIZE; i++) {                                     \
      space::function_page_data_##name[i] = address_##name[i] ^ __TIME__[0];   \
    }                                                                          \
  }

/// Checks if a function's code matches that of its corresponding xorred memory
/// page's.
#define CHECK_FUNCTION_DATA(space, name, action)                               \
  {                                                                            \
    uint8_t *address_##name = PAGE_ALIGN((uint8_t *)&name);                    \
    for (auto i = 0; i < PAGE_SIZE; i++) {                                     \
      if (address_##name[i] !=                                                 \
          (space::function_page_data_##name[i] ^ __TIME__[0])) {               \
        action;                                                                \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
  }

/// Instead of checking if a function's code matches its corresponding xorred
/// memory page's, this code simply extracts the code of the page from memory
/// and writes it back to the function's.
#define HEAL_FUNCTION_DATA(space, name)                                        \
  {                                                                            \
    auto address_##name = PAGE_ALIGN((uint8_t *)&name);                        \
    DWORD old_protection_##name;                                               \
    VirtualProtect(address_##name, PAGE_SIZE, PAGE_EXECUTE_READWRITE,          \
                   &old_protection_##name);                                    \
                                                                               \
    for (auto i = 0; i < PAGE_SIZE; i++) {                                     \
      if (address_##name[i] !=                                                 \
          (space::function_page_data_##name[i] ^ __TIME__[0])) {               \
        address_##name[i] = space::function_page_data_##name[i] ^ __TIME__[0]; \
      }                                                                        \
    }                                                                          \
    VirtualProtect(address_##name, PAGE_SIZE, old_protection_##name,           \
                   &old_protection_##name);                                    \
  }

/// Checks if a function's integrity has been violated, then calls it, executing
/// any action that should be executed if the function's code has been patched
/// too.
#define CHECKED_FUNCTION_CALL(space, name, action, ...)                        \
  [&]() {                                                                      \
    CHECK_FUNCTION_DATA(space, name, action);                                  \
    return name(__VA_ARGS__);                                                  \
  }();

/// Heals a function (removes patches) then calls it.
#define FORCED_FUNCTION_CALL(space, name, ...)                                 \
  [&]() {                                                                      \
    HEAL_FUNCTION_DATA(space, name);                                           \
    return name(__VA_ARGS__);                                                  \
  }();