#pragma once

void hexdump(const char* caption, void* ptr, int buflen);
void dump_to_file(const char* name, void* data, size_t size);
void read_from_file(const char* name, uint8_t*& data, size_t& size);
void* memmem(void* haystack, size_t haystack_len, void* needle, size_t needle_len);

#define MAKE_UINT32(a, b1, b2, b3, b4) (uint8_t)a[b1] | ((uint8_t)a[b2] << 8) | ((uint8_t)a[b3] << 16) | ((uint8_t)a[b4] << 24)
#define PUT_UINT32(a, b1, b2, b3, b4, i) do {\
    a[b1] = i & 0xFF;\
    a[b2] = (i>>8) & 0xFF;\
    a[b3] = (i>>16) & 0xFF;\
    a[b4] = (i>>24) & 0xFF;\
  } while (0)
