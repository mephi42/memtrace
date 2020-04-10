// Copyright (C) 2020, and GNU GPL'd, by mephi42.
#include <stdlib.h>
#include <unistd.h>

/* Must be larger than maximum TLV length, which is 64k. */
char cat_buf[128 * 1024];

int main() {
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
