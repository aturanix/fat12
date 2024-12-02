#include "filesystem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "%s: not enough arguments\n", argv[0]);
    return EXIT_FAILURE;
  }

  int fd = open(argv[1], O_RDWR);
  if (fd == -1) {
    perror("open");
    return EXIT_FAILURE;
  }

  struct stat statbuf;
  if (fstat(fd, &statbuf) == -1) {
    perror("fstat");
    close(fd);
    return EXIT_FAILURE;
  }

  size_t len = statbuf.st_size;
  char *mapping =
      mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);

  struct filesystem fs;
  filesystem_init(&fs, mapping);

  int exit_value = EXIT_SUCCESS;
  if (strcmp(argv[2], "dumpe2fs") == 0 && argc == 3) {
    filesystem_dumpe2fs(&fs);
  } else if (strcmp(argv[2], "dir") == 0 && argc == 4) {
    exit_value = filesystem_dir(&fs, argv[3]);
  } else if (strcmp(argv[2], "mkdir") == 0 && argc == 4) {
    exit_value = filesystem_mkdir(&fs, argv[3]);
  } else if (strcmp(argv[2], "rmdir") == 0 && argc == 4) {
    exit_value = filesystem_rmdir(&fs, argv[3]);
  } else if (strcmp(argv[2], "del") == 0 && argc == 4) {
    exit_value = filesystem_del(&fs, argv[3]);
  } else if (strcmp(argv[2], "write") == 0 && argc == 5) {
    exit_value = filesystem_write(&fs, argv[4], argv[3]);
  } else if (strcmp(argv[2], "read") == 0 && argc == 5) {
    exit_value = filesystem_read(&fs, argv[3], argv[4]);
  } else {
    fprintf(stderr, "%s: wrong or wrong number of arguments\n", argv[0]);
    exit_value = EXIT_FAILURE;
  }

  msync(mapping, len, MS_SYNC);
  munmap(mapping, getpagesize());
  close(fd);
  return exit_value;
}
