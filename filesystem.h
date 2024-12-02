#pragma once

#include <stdbool.h>
#include <stdint.h>

struct bpb {
  uint32_t jump_boot;
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
  uint8_t oem_name[8];
  uint8_t sectors_per_cluster;
  uint8_t number_of_fats;
  uint8_t media;
  uint8_t drive_number;
  uint8_t boot_signature;
  uint8_t volume_label[11];
  uint8_t filesystem_type[8];
};

struct filesystem {
  char *mapping;
  struct bpb bpb;
  uint32_t total_sector_count;
  uint32_t root_dir_sectors;
  uint32_t data_sectors;
  uint32_t count_of_clusters;
  uint32_t first_root_directory_sector;
  uint32_t first_data_sector;
  uint32_t bytes_per_cluster;
  // uint32_t count_of_fat_sectors;
  int fd;
};

void filesystem_init(struct filesystem *fs, char *mapping);
bool filesystem_dir(struct filesystem const *fs, char const *path);
bool filesystem_rmdir(struct filesystem *fs, char const *path);
bool filesystem_mkdir(struct filesystem *fs, char const *path);
bool filesystem_read(struct filesystem const *fs, char const *path_src,
                     char const *path_dst);
bool filesystem_write(struct filesystem *fs, char const *path_src,
                      char const *path_dst);
bool filesystem_del(struct filesystem *fs, char const *path);
void filesystem_dumpe2fs(struct filesystem const *fs);
