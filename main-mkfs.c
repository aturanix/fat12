#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <endian.h>

struct bpb {
  uint32_t volume_id;
  uint32_t hidden_sector_count;
  uint32_t total_sector_count32;
  uint16_t bytes_per_sector;
  uint16_t reserved_sector_count;
  uint16_t root_entry_count;
  uint16_t total_sector_count16;
  uint16_t fat_size16;
  uint16_t sectors_per_track;
  uint16_t number_of_heads;
  uint8_t jump_boot[3];
  uint8_t oem_name[8];
  uint8_t sectors_per_cluster;
  uint8_t number_of_fats;
  uint8_t media;
  uint8_t drive_number;
  uint8_t boot_signature;
  uint8_t volume_label[11];
  uint8_t filesystem_type[8];
};

// 1980 <= year <= 2107
// 1 <= month <= 12
// 1 <= day <= 31
static uint16_t date_encode(uint16_t year, uint8_t month,
                                      uint8_t day) {
  assert(1980 <= year && year <= 2107);
  assert(1 <= month && month <= 12);
  assert(1 <= day && day <= 31);
  return (uint16_t)day | ((uint16_t)month << 5) | ((year - 1980) << 9);
}

// 0 <= hour <= 23
// 0 <= minute <= 59
// 0 <= second <= 59 odd seconds will decremented by one
static uint16_t time_encode(uint8_t hour, uint8_t minute,
                                      uint8_t second) {
  assert(hour <= 23);
  assert(minute <= 59);
  assert(second <= 59);
  return ((uint16_t)hour << 11) | ((uint16_t)minute << 5) |
         ((uint16_t)second >> 1);
}

static uint16_t date_from_timespec(struct timespec *tp) {
  struct tm tm;
  gmtime_r(&tp->tv_sec, &tm);

  return date_encode(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static uint16_t time_from_timespec(struct timespec *tp) {
  return time_encode(tp->tv_sec / 60 / 60 % 24, tp->tv_sec / 60 % 60,
                               tp->tv_sec % 60);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "%s: not right amount of arguments\n", argv[0]);
    return EXIT_FAILURE;
  }

  uint16_t block_size = 0;
  switch (argv[1][0]) {
  case '0':
    if (strcmp(argv[1] + 1, ".5") == 0) {
      block_size = 512;
    }
    break;
  case '1':
    if (argv[1][1] == '\0') {
      block_size = 1024;
    }
    break;
  case '2':
    if (argv[1][1] == '\0') {
      block_size = 2048;
    }
    break;
  case '4':
    if (argv[1][1] == '\0') {
      block_size = 4096;
    }
    break;
  }

  if (block_size == 0) {
    fprintf(stderr, "%s: unsupported block size\n", argv[0]);
    return EXIT_FAILURE;
  }

  int fd =
      open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR);
  if (fd == -1) {
    perror("open");
    return EXIT_FAILURE;
  }

  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);

  uint16_t bytes_per_sector = 512;
  uint8_t sectors_per_cluster = block_size / bytes_per_sector;
  uint16_t root_entry_count = block_size == 4096 ? 2048 : 512;

  struct bpb bpb = {.jump_boot = {0xEB, 0x3C, 0x90},
      .oem_name = {'A', 'L', 'I', 'H', 'A', 'N', ' ', ' '},
      .bytes_per_sector = bytes_per_sector,
      .sectors_per_cluster = sectors_per_cluster,
      .reserved_sector_count = sectors_per_cluster,
      .number_of_fats = 1,
      .root_entry_count = root_entry_count,
      .total_sector_count16 = 0,
      .fat_size16 = 12,
      .media = 0xF8,
      .sectors_per_track = 32,
      .number_of_heads = 2,
      .hidden_sector_count = 0,
      .drive_number = 0x80,
      .total_sector_count32 = 4096U * sectors_per_cluster,
      .boot_signature = 0x29,
      .volume_id = ((uint32_t)date_from_timespec(&tp) << 16) | time_from_timespec(&tp),
      .volume_label = {'N', 'O', ' ', 'N', 'A' ,'M', 'E', ' ', ' ', ' ', ' '},
      .filesystem_type = {'F', 'A', 'T', '1', '2', ' ', ' ', ' '},
  };

  size_t volume_size = bpb.bytes_per_sector * bpb.total_sector_count32;
  if (ftruncate(fd, volume_size) == -1) {
    perror("ftruncate");
    close(fd);
    return EXIT_FAILURE;
  }

  uint8_t boot_sector[512];

  memcpy(boot_sector, bpb.jump_boot, sizeof bpb.jump_boot);

  memcpy(boot_sector + 3, bpb.oem_name, sizeof bpb.oem_name);

  boot_sector[11] = bpb.bytes_per_sector & 0xFF;
  boot_sector[12] = (bpb.bytes_per_sector >> 8) & 0xFF;

  boot_sector[13] = bpb.sectors_per_cluster;

  *(uint16_t *)(boot_sector + 14) = htole16(bpb.reserved_sector_count);

  boot_sector[16] = bpb.number_of_fats;

  boot_sector[17] = bpb.root_entry_count & 0xFF;
  boot_sector[18] = (bpb.root_entry_count >> 8) & 0xFF;

  boot_sector[19] = bpb.total_sector_count16 & 0xFF;
  boot_sector[20] = (bpb.total_sector_count16 >> 8) & 0xFF;

  boot_sector[21] = bpb.media;

  *(uint16_t *)(boot_sector + 22) = htole16(bpb.fat_size16);

  *(uint16_t *)(boot_sector + 24) = htole16(bpb.sectors_per_track);

  *(uint16_t *)(boot_sector + 26) = htole16(bpb.number_of_heads);

  *(uint32_t *)(boot_sector + 28) = htole32(bpb.hidden_sector_count);

  *(uint32_t *)(boot_sector + 32) = htole32(bpb.total_sector_count32);

  boot_sector[36] = bpb.drive_number;

  boot_sector[37] = 0x0;

  boot_sector[38] = bpb.boot_signature;

  boot_sector[39] = bpb.volume_id & 0xFF;
  boot_sector[40] = (bpb.volume_id >> 8) & 0xFF;
  boot_sector[41] = (bpb.volume_id >> 16) & 0xFF;
  boot_sector[42] = (bpb.volume_id >> 24) & 0xFF;

  memcpy(boot_sector + 43, bpb.volume_label, sizeof bpb.volume_label);

  memcpy(boot_sector + 54, bpb.filesystem_type, sizeof bpb.filesystem_type);

  memset(boot_sector + 62, 0, 448);

  boot_sector[510] = 0x55;
  boot_sector[511] = 0xAA;

  if (pwrite(fd, boot_sector, sizeof boot_sector, 0) == -1) {
      perror("pwrite: boot_sector");
      close(fd);
      return EXIT_FAILURE;
  }

  uint8_t reserved_fat_entries[] = {bpb.media, 0xFF, 0xFF};
  off_t fat_offset = (uint32_t)bpb.reserved_sector_count * bpb.bytes_per_sector;
  if (pwrite(fd, reserved_fat_entries, sizeof reserved_fat_entries, fat_offset) == -1) {
      perror("pwrite: reserved_fat_entries");
      close(fd);
      return EXIT_FAILURE;
  }

  close(fd);
}
