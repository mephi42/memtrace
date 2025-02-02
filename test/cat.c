// Copyright (C) 2020-2025, and GNU GPL'd, by mephi42.
#include <stdlib.h>
#include <unistd.h>

/* Must be larger than the maximum TLV length, which is 64k. */
char cat_buf[64 * 1024 + 256];

/* Serves two purposes:
 * - Fills cat_buf with data that is different from what the test will write.
 * - Creates a lot of small defs. */
static void init_cat_buf() {
  for (size_t i = 0; i < sizeof(cat_buf); i++) cat_buf[i] = (char)((~i) & 0xff);
}

int main() {
  init_cat_buf();
  while (1) {
    ssize_t r = read(STDIN_FILENO, cat_buf, sizeof(cat_buf));
    if (r == 0) break;
    if (r < 0) return EXIT_FAILURE;
    char* p = cat_buf;
    while (r > 0) {
      ssize_t w = write(STDOUT_FILENO, p, (size_t)r);
      if (w < 0) return EXIT_FAILURE;
      p += w;
      r -= w;
    }
  }
}
