#include "filesystem.h"

#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define DIRECTORY_SIZE 32

enum attribute {
  ATTR_READ_ONLY = 0x01,
  ATTR_HIDDEN = 0x02,
  ATTR_SYSTEM = 0x04,
  ATTR_VOLUME_ID = 0x08,
  ATTR_DIRECTORY = 0x10,
  ATTR_ARCHIVE = 0x20,
};

struct directory {
  uint32_t file_size;
  uint16_t creation_time;
  uint16_t creation_date;
  uint16_t last_access_date;
  uint16_t write_time;
  uint16_t write_date;
  uint16_t first_cluster_low;
  uint8_t name[11];
  uint8_t attribute;
  uint8_t creation_time_tenth;
};

static uint16_t aligned_le16toh(void const *p) {
  return le16toh(*(uint16_t const *)p);
}

static uint16_t unaligned_le16toh(void const *p) {
  uint16_t n;
  memcpy(&n, p, 2);
  return le16toh(n);
}

static uint32_t aligned_le32toh(void const *p) {
  return le32toh(*(uint32_t const *)p);
}

static uint32_t unaligned_le32toh(void const *p) {
  uint32_t n;
  memcpy(&n, p, 2);
  return le32toh(n);
}

static uint16_t fat_entry_of_cluster(struct filesystem const *fs,
                                     uint16_t cluster_number) {
  // uint32_t fat_offset = cluster_number + cluster_number / 2;
  // uint32_t this_fat_sector_number = (uint32_t)fs->bpb.reserved_sector_count +
  // fat_offset / fs->bpb.bytes_per_sector; uint32_t this_fat_entry_offset =
  // fat_offset % fs->bpb.bytes_per_sector;
  uint32_t fat_offset = (uint32_t)fs->bpb.reserved_sector_count *
                            (uint32_t)fs->bpb.bytes_per_sector +
                        (uint32_t)cluster_number + (uint32_t)cluster_number / 2;

  uint16_t fat_entry_value = unaligned_le16toh(fs->mapping + fat_offset);
  return (cluster_number % 2 == 0) ? (fat_entry_value & 0x0FFF)
                                   : (fat_entry_value >> 4);
}

static void set_fat_entry_of_cluster(struct filesystem const *fs,
                                     uint16_t cluster_number, uint16_t entry) {
  // uint32_t fat_offset = cluster_number + cluster_number / 2;
  // uint32_t this_fat_sector_number = (uint32_t)fs->bpb.reserved_sector_count +
  // fat_offset / fs->bpb.bytes_per_sector; uint32_t this_fat_entry_offset =
  // fat_offset % fs->bpb.bytes_per_sector;
  uint32_t fat_offset = (uint32_t)fs->bpb.reserved_sector_count *
                            (uint32_t)fs->bpb.bytes_per_sector +
                        (uint32_t)cluster_number + (uint32_t)cluster_number / 2;

  uint16_t fat_entry_value = unaligned_le16toh(fs->mapping + fat_offset);
  fat_entry_value = (cluster_number % 2 == 0)
                        ? ((fat_entry_value & 0xF000) | entry)
                        : (fat_entry_value & 0x000F) | (entry << 4);
  fs->mapping[fat_offset] = fat_entry_value;
  fs->mapping[fat_offset + 1] = fat_entry_value >> 8;
}

static uint16_t find_free_cluster(struct filesystem const *fs) {
  for (size_t cluster = 2; cluster != fs->count_of_clusters; ++cluster) {
    if (fat_entry_of_cluster(fs, cluster) == 0x000) {
      return cluster;
    }
  }

  return 0;
}

static void directory_init(struct directory *d, uint8_t *src) {
  memcpy(d->name, src, 11);
  d->attribute = src[11];
  d->creation_time_tenth = src[13];
  d->creation_time = aligned_le16toh(src + 14);
  d->creation_date = aligned_le16toh(src + 16);
  d->last_access_date = aligned_le16toh(src + 18);
  d->write_time = aligned_le16toh(src + 22);
  d->write_date = aligned_le16toh(src + 24);
  d->first_cluster_low = aligned_le16toh(src + 26);
  d->file_size = aligned_le32toh(src + 28);
}

static void directory_write(struct directory const *d, uint8_t *dst) {
  memcpy(dst, d->name, 11);
  dst[11] = d->attribute;
  dst[12] = 0;
  dst[13] = d->creation_time_tenth;
  *(uint16_t *)(dst + 14) = htole16(d->creation_time);
  *(uint16_t *)(dst + 16) = htole16(d->creation_date);
  *(uint16_t *)(dst + 18) = htole16(d->last_access_date);
  *(uint16_t *)(dst + 20) = 0;
  *(uint16_t *)(dst + 22) = htole16(d->write_time);
  *(uint16_t *)(dst + 24) = htole16(d->write_date);
  *(uint16_t *)(dst + 26) = htole16(d->first_cluster_low);
  *(uint32_t *)(dst + 28) = htole16(d->file_size);
}

// 1980 <= year <= 2107
// 1 <= month <= 12
// 1 <= day <= 31
static uint16_t directory_date_encode(uint16_t year, uint8_t month,
                                      uint8_t day) {
  assert(1980 <= year && year <= 2107);
  assert(1 <= month && month <= 12);
  assert(1 <= day && day <= 31);
  return (uint16_t)day | ((uint16_t)month << 5) | ((year - 1980) << 9);
}

static void directory_date_decode(uint16_t *year, uint8_t *month, uint8_t *day,
                                  uint16_t date) {
  *day = date & 0x1F;
  *month = (date >> 5) & 0x0F;
  *year = ((date >> 9) & 0x7F) + 1980;
}

// 0 <= hour <= 23
// 0 <= minute <= 59
// 0 <= second <= 59 odd seconds will decremented by one
static uint16_t directory_time_encode(uint8_t hour, uint8_t minute,
                                      uint8_t second) {
  assert(hour <= 23);
  assert(minute <= 59);
  assert(second <= 59);
  return ((uint16_t)hour << 11) | ((uint16_t)minute << 5) |
         ((uint16_t)second >> 1);
}

static void directory_time_decode(uint8_t *hour, uint8_t *minute,
                                  uint8_t *second, uint16_t t) {
  *second = (t & 0x1F) << 1;
  *minute = (t >> 5) & 0x3F;
  *hour = (t >> 11) & 0x1F;
}

static uint16_t directory_date_from_timespec(struct timespec *tp) {
  struct tm tm;
  gmtime_r(&tp->tv_sec, &tm);

  return directory_date_encode(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

static uint16_t directory_time_from_timespec(struct timespec *tp) {
  return directory_time_encode(tp->tv_sec / 60 / 60 % 24, tp->tv_sec / 60 % 60,
                               tp->tv_sec % 60);
}

static uint8_t directory_time_tenth_from_timespec(struct timespec *tp) {
  return tp->tv_sec % 2 * 100 + tp->tv_nsec / 10000000;
}

static time_t time_from_directory_date_and_time(uint16_t date, uint16_t time) {
  uint16_t year;
  uint8_t month, day;
  uint8_t hour, minute, second;

  directory_date_decode(&year, &month, &day, date);
  directory_time_decode(&hour, &minute, &second, time);

  struct tm tm = {
      .tm_sec = second,
      .tm_min = minute,
      .tm_hour = hour,
      .tm_mday = day,
      .tm_mon = month - 1,
      .tm_year = year - 1900,
  };

  return timegm(&tm);
}

static bool directory_name_encode(uint8_t *dst, char const *src, size_t len) {
  if (len == 0 || src[0] == ' ') {
    return false;
  }

  if (len == 1 && src[0] == '.') {
    dst[0] = '.';
    memset(dst + 1, 0x20, 10);
    return true;
  } else if (len == 2 && src[0] == '.' && src[1] == '.') {
    dst[0] = '.';
    dst[1] = '.';
    memset(dst + 2, 0x20, 9);
    return true;
  }

  for (size_t i = 0; i != len; ++i) {
    if (src[i] < 0x20) {
      return false;
    }

    switch (src[i]) {
    case 0x22:
    case 0x2A:
    case 0x2B:
    case 0x2C:
    // case 0x2E:
    case 0x2F:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x7C:
      return false;
    }
  }

  char const *name_begin = NULL, *ext_begin = NULL;
  size_t name_len, ext_len;

  char const *dot = memchr(src, '.', len);
  if (dot && memchr(dot + 1, '.', len - (dot - src) - 1)) { // second dot search
    return false;
  }

  if (!dot) {
    name_begin = src;
    name_len = len;

    ext_len = 0;
  } else if (dot - src == 1) {
    name_len = 0;

    ext_begin = src + 1;
    ext_len = len - 1;
  } else {
    name_begin = src;
    name_len = dot - src;

    ext_begin = dot + 1;
    ext_len = len - name_len - 1;
  }

  if (name_len > 8 || ext_len > 3) {
    return false;
  }

  for (size_t i = 0; i < name_len; ++i) {
    dst[i] = toupper(name_begin[i]);
  }
  memset(dst + name_len, 0x20, 8 - name_len);

  for (size_t i = 0; i < ext_len; ++i) {
    dst[8 + i] = toupper(ext_begin[i]);
  }
  memset(dst + 8 + ext_len, 0x20, 3 - ext_len);

  return true;
}

static void directory_name_decode(char *dst, uint8_t const *src) {
  if (src[0] == '.') {
    if (src[1] == '.') {
      dst[0] = '.';
      dst[1] = '.';
      dst[2] = '\0';
    } else {
      dst[0] = '.';
      dst[1] = '\0';
    }

    return;
  }

  for (size_t i = 0; i != 8 && src[i] != 0x20; ++i) {
    *(dst++) = src[i];
  }
  if (src[8] == 0x20) {
    *dst = '\0';
    return;
  }

  *(dst++) = '.';

  for (size_t i = 8; i != 11 && src[i] != 0x20; ++i) {
    *(dst++) = src[i];
  }
  *dst = '\0';
}

static uint32_t first_sector_of_cluster(struct filesystem const *fs,
                                        uint16_t cluster) {
  return (cluster - 2) * (uint32_t)fs->bpb.sectors_per_cluster +
         fs->first_data_sector;
}

static uint8_t *addr_of_cluster(struct filesystem const *fs, uint16_t cluster) {
  return (uint8_t *)fs->mapping + first_sector_of_cluster(fs, cluster) *
                                      (uint32_t)fs->bpb.bytes_per_sector;
}

static void directory_print_stat(struct directory const *d) {
  if (d->name[0] == 0xE5) {
    printf("Free directory entry\n");
    return;
  }

  char name[13];
  directory_name_decode(name, d->name);
  printf("Name: \"%s\"\n", name);

  printf("Attributes:");
  if (d->attribute & ATTR_READ_ONLY) {
    printf(" ATTR_READ_ONLY");
  }
  if (d->attribute & ATTR_HIDDEN) {
    printf(" ATTR_HIDDEN");
  }
  if (d->attribute & ATTR_SYSTEM) {
    printf(" ATTR_SYSTEM");
  }
  if (d->attribute & ATTR_VOLUME_ID) {
    printf(" ATTR_VOLUME_ID");
  }
  if (d->attribute & ATTR_DIRECTORY) {
    printf(" ATTR_DIRECTORY");
  }
  if (d->attribute & ATTR_ARCHIVE) {
    printf(" ATTR_ARCHIVE");
  }
  putchar('\n');

  uint8_t hour, minute, second;
  directory_time_decode(&hour, &minute, &second, d->creation_time);
  printf("Creation time: %.2u:%.2u:%.2u.%u\n", hour, minute,
         second + d->creation_time_tenth / 100, d->creation_time_tenth % 100);

  uint16_t year;
  uint8_t month;
  uint8_t day;
  directory_date_decode(&year, &month, &day, d->creation_date);
  printf("Creation date: %u-%.2u-%.2u\n", year, month, day);

  directory_date_decode(&year, &month, &day, d->last_access_date);
  printf("Last access date: %u-%.2u-%.2u\n", year, month, day);

  directory_time_decode(&hour, &minute, &second, d->write_time);
  printf("Last modification time: %.2u:%.2u:%.2u\n", hour, minute, second);

  directory_date_decode(&year, &month, &day, d->write_date);
  printf("Last modification date: %u-%.2u-%.2u\n", year, month, day);

  printf("First cluster: %u\n", d->first_cluster_low);

  printf("Size: %u bytes\n", d->file_size);
}

static uint8_t *filesystem_search_root_directory(struct filesystem const *fs,
                                                 uint8_t const *name) {
  // name offset 0 length 11
  uint8_t *begin =
      (uint8_t *)fs->mapping +
      fs->first_root_directory_sector * (uint32_t)fs->bpb.bytes_per_sector;
  uint8_t *end = begin + (uint32_t)fs->bpb.root_entry_count * 32;
  for (; begin != end; begin += DIRECTORY_SIZE) {
    if (begin[0] == 0xE5) {
      continue;
    } else if (begin[0] == 0x00) {
      return NULL;
    }

    if (memcmp(begin, name, 11) == 0) {
      return begin;
    }
  }

  return NULL;
}

static uint8_t *filesystem_search_directory(struct filesystem const *fs,
                                            uint8_t *dir_addr,
                                            uint8_t const *name) {
  // attribute offset 11 length 1
  if (dir_addr[11] != ATTR_DIRECTORY) {
    return NULL;
  }
  // cluster offset 26 length 2
  uint16_t cluster = aligned_le16toh(dir_addr + 26);
  // name offset 0 length 11
  while (2 <= cluster && cluster <= fs->count_of_clusters + 1) {
    uint8_t *begin = addr_of_cluster(fs, cluster);
    uint8_t *end = begin + fs->bytes_per_cluster;
    for (; begin != end; begin += DIRECTORY_SIZE) {
      if (begin[0] == 0xE5) {
        continue;
      } else if (begin[0] == 0x00) {
        return NULL;
      }

      if (memcmp(begin, name, 11) == 0) {
        return begin;
      }
    }

    cluster = fat_entry_of_cluster(fs, cluster);
  }

  return NULL;
}

static uint8_t *
filesystem_follow_path_root_excluded(struct filesystem const *fs, uint8_t *addr,
                                     char const *path,
                                     bool return_last_parent) {
  // attribute offset 11 length 1
  while (addr && path[0] != '\0' && path[0] != '\\' && (addr[11] & ATTR_DIRECTORY)) {
    uint8_t name[11];
    char *slash = strchr(path, '\\');
    if (!slash) {
      if (return_last_parent) {
        return addr;
      }

      if (!directory_name_encode(name, path, strlen(path))) {
        return NULL;
      }

      return filesystem_search_directory(fs, addr, name);
    }

    size_t len = slash - path;
    if (len > 12) {
      return NULL;
    }

    char namecp[13];
    memcpy(namecp, path, len);
    namecp[len] = '\0';

    if (!directory_name_encode(name, path, len)) {
      return NULL;
    }
    addr = filesystem_search_directory(fs, addr, name);
    path = slash + 1;
  }

  return NULL;
}

static uint8_t *filesystem_follow_path(struct filesystem const *fs,
                                       char const *path,
                                       bool return_last_parent) {
  if (path[0] != '\\') {
    return NULL;
  }

  ++path;

  if (*path == '\0') {
    return (uint8_t *)fs->mapping +
           fs->first_root_directory_sector * (uint32_t)fs->bpb.bytes_per_sector;
  }

  uint8_t name[11];
  char *slash = strchr(path, '\\');
  if (!slash) {
    if (!directory_name_encode(name, path, strlen(path))) {
      return NULL;
    }

    return filesystem_search_root_directory(fs, name);
  }

  size_t len = slash - path;
  if (len > 12) {
    return NULL;
  }

  char namecp[13];
  memcpy(namecp, path, len);
  namecp[len] = '\0';

  if (!directory_name_encode(name, namecp, len)) {
    return NULL;
  }

  uint8_t *addr = filesystem_search_root_directory(fs, name);
  if (!addr) {
    return NULL;
  }

  return filesystem_follow_path_root_excluded(fs, addr, slash + 1,
                                              return_last_parent);
}

static void dir_row(struct directory const *d) {
  time_t time = time_from_directory_date_and_time(d->write_date, d->write_time);

  struct tm tm;
  localtime_r(&time, &tm);

  printf("%u-%.2u-%.2u ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
  printf("%.2u:%.2u:%.2u\t", tm.tm_hour, tm.tm_min, tm.tm_sec);

  if (d->attribute & ATTR_DIRECTORY) {
    printf("<DIR>\t");
  } else {
    putchar('\t');
  }

  printf("%'15d", d->file_size);

  char name[13];
  directory_name_decode(name, d->name);
  printf(" %s\n", name);
}

static void directory_print_range(uint8_t *begin, uint8_t *end,
                                  uint32_t *directories, uint64_t *file_size,
                                  uint32_t *files) {
  for (; begin != end; begin += DIRECTORY_SIZE) {
    struct directory d;
    directory_init(&d, begin);
    if (d.name[0] == 0xE5) {
      break;
    } else if (d.name[0] == 0x00 || (d.attribute & ATTR_HIDDEN)) {
      continue;
    }

    dir_row(&d);
    if (d.attribute & ATTR_DIRECTORY) {
      ++(*directories);
    } else {
      ++(*files);
    }

    *file_size += d.file_size;
  }
}

static bool filesystem_range_has_no_entries(uint8_t *begin, uint8_t *end) {
  for (; begin != end; begin += DIRECTORY_SIZE) {
    if (memcmp(begin, ".          ", 11) == 0 ||
        memcmp(begin, "..         ", 11) == 0) {
      continue;
    }

    if (begin[0] == 0x00) {
      return true;
    } else if (begin[0] != 0xE5) {
      return false;
    }
  }

  return true;
}

static uint8_t *cluster_find_free_entry(uint8_t *begin, uint8_t *end) {
  for (; begin != end; begin += DIRECTORY_SIZE) {
    if (begin[0] == 0x00 || begin[0] == 0xE5) {
      return begin;
    }
  }

  return NULL;
}

static uint8_t *filesystem_directory_find_free_entry(struct filesystem *fs,
                                                     uint16_t cluster) {
  while (2 <= cluster && cluster < fs->count_of_clusters) {
    uint8_t *begin = addr_of_cluster(fs, cluster);
    uint8_t *end = begin + fs->bytes_per_cluster;

    uint8_t *entry = cluster_find_free_entry(begin, end);
    if (entry) {
      return entry;
    }

    cluster = fat_entry_of_cluster(fs, cluster);
  }

  return false;
}

static bool filesystem_directory_is_empty(struct filesystem *fs,
                                          uint32_t cluster) {
  while (2 <= cluster && cluster < fs->count_of_clusters) {
    uint8_t *begin = addr_of_cluster(fs, cluster);
    uint8_t *end = begin + fs->bytes_per_cluster;
    if (!filesystem_range_has_no_entries(begin, end)) {
      return false;
    }

    cluster = fat_entry_of_cluster(fs, cluster);
  }

  return true;
}

static void filesystem_dealloc_cluster_chain(struct filesystem *fs,
                                             uint32_t cluster) {
  for (;;) {
    uint32_t next_cluster = fat_entry_of_cluster(fs, cluster);
    set_fat_entry_of_cluster(fs, cluster, 0x000);

    if (next_cluster < 2 || next_cluster >= fs->count_of_clusters) {
      break;
    }

    cluster = next_cluster;
  }
}

void filesystem_init(struct filesystem *fs, char *mapping) {
  fs->mapping = mapping;

  fs->bpb.jump_boot = (uint32_t)mapping[0] || ((uint32_t)mapping[1] << 8) ||
                      ((uint32_t)mapping[2] << 16);

  memcpy(fs->bpb.oem_name, mapping + 3, 8);
  fs->bpb.bytes_per_sector = unaligned_le16toh(mapping + 11);
  fs->bpb.sectors_per_cluster = mapping[13];
  fs->bpb.reserved_sector_count = aligned_le16toh(mapping + 14);
  fs->bpb.number_of_fats = mapping[16];
  fs->bpb.root_entry_count = unaligned_le16toh(mapping + 17);
  fs->bpb.total_sector_count16 = unaligned_le16toh(mapping + 19);
  fs->bpb.media = mapping[21];
  fs->bpb.fat_size16 = aligned_le16toh(mapping + 22);
  fs->bpb.sectors_per_track = aligned_le16toh(mapping + 24);
  fs->bpb.number_of_heads = aligned_le16toh(mapping + 26);
  fs->bpb.hidden_sector_count = aligned_le32toh(mapping + 28);
  fs->bpb.total_sector_count32 = aligned_le32toh(mapping + 32);
  fs->bpb.drive_number = mapping[36];
  fs->bpb.volume_id = unaligned_le32toh(mapping + 39);
  memcpy(fs->bpb.volume_label, mapping + 43, 11);
  memcpy(fs->bpb.filesystem_type, mapping + 54, 8);

  fs->total_sector_count = (fs->bpb.total_sector_count16 != 0)
                               ? fs->bpb.total_sector_count16
                               : fs->bpb.total_sector_count32;
  fs->root_dir_sectors = ((uint32_t)fs->bpb.root_entry_count * DIRECTORY_SIZE +
                          (uint32_t)fs->bpb.bytes_per_sector - 1) /
                         (uint32_t)fs->bpb.bytes_per_sector;
  fs->data_sectors =
      fs->total_sector_count -
      ((uint32_t)fs->bpb.reserved_sector_count +
       (uint32_t)fs->bpb.number_of_fats * (uint32_t)fs->bpb.fat_size16 +
       fs->root_dir_sectors);
  // Microsoft documentation says count of clusters should be set less than
  // calculated value
  fs->count_of_clusters = fs->data_sectors / fs->bpb.sectors_per_cluster - 30;
  fs->first_data_sector =
      (uint32_t)fs->bpb.reserved_sector_count +
      (uint32_t)fs->bpb.number_of_fats * (uint32_t)fs->bpb.fat_size16 +
      fs->root_dir_sectors;
  fs->first_root_directory_sector =
      fs->first_data_sector - fs->root_dir_sectors;
  fs->bytes_per_cluster = (uint32_t)fs->bpb.bytes_per_sector *
                          (uint32_t)fs->bpb.sectors_per_cluster;
  // fs->count_of_fat_sectors = (fs->count_of_clusters + fs->count_of_clusters /
  // 2 + (uint32_t)fs->bpb.bytes_per_sector - 1) /
  // (uint32_t)fs->bpb.bytes_per_sector;
}

bool filesystem_dir(struct filesystem const *fs, char const *path) {
  if (path[0] != '\\') {
    fprintf(stderr, "Path must start with root\n");
    return false;
  }

  printf(" Volume Serial Number is %.4X-%.4X\n\n", fs->bpb.volume_id >> 16,
         fs->bpb.volume_id & 0x0000FFFF);
  printf(" Directory of %s\n\n", path);
  uint32_t directories = 0;
  uint32_t files = 0;
  uint64_t file_size = 0;
  if (path[1] == '\0') {
    uint8_t *begin =
        (uint8_t *)fs->mapping +
        fs->first_root_directory_sector * (uint32_t)fs->bpb.bytes_per_sector;
    uint8_t *end = begin + (uint32_t)fs->bpb.root_entry_count * 32;
    directory_print_range(begin, end, &directories, &file_size,
                          &files);
  } else {
    uint8_t *d = filesystem_follow_path(fs, path, false);
    if (!d) {
      fprintf(stderr, "Does not exist\n");
      return false;
    }

    struct directory di;
    directory_init(&di, d);
    if (!(di.attribute & ATTR_DIRECTORY)) {
      fprintf(stderr, "Not a directory\n");
      return false;
    }

    uint32_t cluster = di.first_cluster_low;
    while (2 <= cluster && cluster < fs->count_of_clusters) {
      uint8_t *begin =
          (uint8_t *)fs->mapping + first_sector_of_cluster(fs, cluster) *
                                       (uint32_t)fs->bpb.bytes_per_sector;
      uint8_t *end = begin + fs->bytes_per_cluster;

      directory_print_range(begin, end, &directories, &file_size, &files);
      cluster = fat_entry_of_cluster(fs, cluster);
    }
  }

  printf("\t\t%u File(s)\t%'15lu bytes\n", files, file_size);
  printf("\t\t%u Dir(s)\n", directories);
  return true;
}

bool filesystem_rmdir(struct filesystem *fs, char const *path) {
  if (path[0] != '\\') {
    fprintf(stderr, "Path must start with root\n");
    return false;
  }

  if (path[1] == '\0') {
    fprintf(stderr, "Root cannot be removed\n");
    return false;
  }

  uint8_t *addr = filesystem_follow_path(fs, path, false);
  if (!addr) {
    fprintf(stderr, "Does not exist\n");
    return false;
  }

  struct directory d;
  directory_init(&d, addr);
  if (!(d.attribute & ATTR_DIRECTORY)) {
    fprintf(stderr, "Not a directory\n");
    return false;
  } else if (d.attribute & ATTR_READ_ONLY) {
    fprintf(stderr, "Is read-only\n");
    return false;
  } else if (d.attribute & ATTR_SYSTEM) {
    fprintf(stderr, "Is a system directory\n");
    return false;
  } else if (d.attribute & ATTR_VOLUME_ID) {
    fprintf(stderr, "Is volume id\n");
    return false;
  }

  if (!filesystem_directory_is_empty(fs, d.first_cluster_low)) {
    fprintf(stderr, "Directory is not empty\n");
    return false;
  }

  if (strchr(path + 1, '\\')) {
    uint8_t *parent = filesystem_follow_path(fs, path, true);

    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    uint16_t time = directory_time_from_timespec(&tp);
    uint16_t date = directory_date_from_timespec(&tp);
    // last access time offset 18 length 2
    *(uint16_t *)(parent + 18) = htole16(date);
    // write time offset 22 length 2
    *(uint16_t *)(parent + 22) = htole16(time);
    // write date offset 24 length 2
    *(uint16_t *)(parent + 24) = htole16(date);
  }

  filesystem_dealloc_cluster_chain(fs, d.first_cluster_low);
  // mark as free
  addr[0] = 0xE5;
  return true;
}

bool filesystem_mkdir(struct filesystem *fs, char const *path) {
  if (path[0] != '\\') {
    fprintf(stderr, "Path must start with root\n");
    return false;
  }

  uint8_t *target = filesystem_follow_path(fs, path, false);
  if (target) {
    fprintf(stderr, "Entry already exists\n");
    return false;
  }

  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  uint16_t time = directory_time_from_timespec(&tp);
  uint16_t date = directory_date_from_timespec(&tp);
  uint8_t time_tenth = directory_time_tenth_from_timespec(&tp);

  struct directory d = {.attribute = ATTR_DIRECTORY,
                        .creation_time_tenth = time_tenth,
                        .creation_time = time,
                        .creation_date = date,
                        .last_access_date = date,
                        .write_time = time,
                        .write_date = date,
                        .file_size = 0};

  char *last_slash = strrchr(path, '\\');
  if (!directory_name_encode(d.name, last_slash + 1, strlen(last_slash + 1))) {
    fprintf(stderr, "Filename is unappropriate\n");
    return false;
  }

  uint16_t cluster;
  for (cluster = 2; cluster != fs->count_of_clusters; ++cluster) {
    if (fat_entry_of_cluster(fs, cluster) == 0x000) {
      break;
    }
  }

  if (cluster == fs->count_of_clusters) {
    fprintf(stderr, "No free clusters\n");
  }

  d.first_cluster_low = cluster;

  struct directory dot = {
      .name = {'.', 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
      .attribute = ATTR_DIRECTORY,
      .creation_time_tenth = time_tenth,
      .creation_time = time,
      .creation_date = date,
      .last_access_date = date,
      .write_time = time,
      .write_date = date,
      .first_cluster_low = cluster,
      .file_size = 0};

  struct directory dotdot = {
      .name = {'.', '.', 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20},
      .attribute = ATTR_DIRECTORY,
      .creation_time_tenth = time_tenth,
      .creation_time = time,
      .creation_date = date,
      .last_access_date = date,
      .write_time = time,
      .write_date = date,
      .file_size = 0};

  uint8_t *free_entry;
  // mkdir in root
  if (!strchr(path + 1, '\\')) {
    dotdot.first_cluster_low = 0;
    uint8_t *begin =
        (uint8_t *)fs->mapping +
        fs->first_root_directory_sector * (uint32_t)fs->bpb.bytes_per_sector;
    uint8_t *end = begin + (uint32_t)fs->bpb.root_entry_count * DIRECTORY_SIZE;
    free_entry = cluster_find_free_entry(begin, end);
    if (!free_entry) {
      fprintf(stderr, "Root directory is full\n");
      return false;
    }
  } else {
    uint8_t *parent = filesystem_follow_path(fs, path, true);
    if (!parent) {
      fprintf(stderr, "Parent directory does not exist\n");
      return false;
    }

    // first cluster low offset 26 length 2
    dotdot.first_cluster_low = aligned_le16toh(parent + 26);

    free_entry =
        filesystem_directory_find_free_entry(fs, dotdot.first_cluster_low);
    if (!free_entry) {
      fprintf(stderr, "Parent directory is full\n");
      return false;
    }

    // last access time offset 18 length 2
    *(uint16_t *)(parent + 18) = date;
    // write time offset 22 length 2
    *(uint16_t *)(parent + 22) = time;
    // write date offset 24 length 2
    *(uint16_t *)(parent + 24) = date;
  }

  set_fat_entry_of_cluster(fs, cluster, 0xFFF);
  directory_write(&d, free_entry);

  uint8_t *addr = addr_of_cluster(fs, cluster);
  directory_write(&dot, addr);
  directory_write(&dotdot, addr + DIRECTORY_SIZE);

  memset(addr + 2 * DIRECTORY_SIZE, 0,
         fs->bytes_per_cluster - 2 * DIRECTORY_SIZE);
  return true;
}

bool filesystem_read(struct filesystem const *fs, char const *path_src,
                     char const *path_dst) {
  if (path_src[0] != '\\') {
    fprintf(stderr, "Path must start with root\n");
    return false;
  }

  uint8_t *src = filesystem_follow_path(fs, path_src, false);
  if (!src) {
    fprintf(stderr, "Source path does not exist\n");
    return false;
  }

  struct directory d;
  directory_init(&d, src);
  if (d.attribute & ATTR_DIRECTORY) {
    fprintf(stderr, "Source file is a directory\n");
    return false;
  }

  FILE *f = fopen(path_dst, "w");
  if (!f) {
    perror("Destination");
    return false;
  }

  uint16_t cluster = d.first_cluster_low;
  uint32_t file_size = d.file_size;

  while (file_size != 0 && 2 <= cluster &&
         cluster <= fs->count_of_clusters + 1) {
    uint8_t *begin = addr_of_cluster(fs, cluster);

    size_t nmemb =
        (file_size < fs->bytes_per_cluster) ? file_size : fs->bytes_per_cluster;

    if (fwrite(begin, 1, nmemb, f) != nmemb) {
      fprintf(stderr, "Problem while writing to destination\n");
      fclose(f);
      return false;
    }

    file_size -= nmemb;

    cluster = fat_entry_of_cluster(fs, cluster);
  }

  if (file_size != 0) {
    fprintf(stderr, "Could not write full file\n");
    return false;
  }

  fclose(f);
  return true;
}

bool filesystem_write(struct filesystem *fs, char const *path_src,
                      char const *path_dst) {
  if (path_dst[0] != '\\') {
    fprintf(stderr, "Path must start with root\n");
    return false;
  }

  uint8_t *target = filesystem_follow_path(fs, path_dst, false);
  if (target) {
    fprintf(stderr, "Entry already exists\n");
    return false;
  }

  FILE *f = fopen(path_src, "r");
  if (!f) {
    perror("Source");
    return false;
  }

  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  uint16_t time = directory_time_from_timespec(&tp);
  uint16_t date = directory_date_from_timespec(&tp);
  uint8_t time_tenth = directory_time_tenth_from_timespec(&tp);

  struct directory d = {.attribute = ATTR_ARCHIVE,
                        .creation_time_tenth = time_tenth,
                        .creation_time = time,
                        .creation_date = date,
                        .last_access_date = date,
                        .write_time = time,
                        .write_date = date,
                        .file_size = 0};

  char *last_slash = strrchr(path_dst, '\\');
  if (!directory_name_encode(d.name, last_slash + 1, strlen(last_slash + 1))) {
    fprintf(stderr, "Filename is unappropriate\n");
    return false;
  }

  uint16_t cluster = find_free_cluster(fs);
  if (cluster == 0) {
    fprintf(stderr, "No free clusters\n");
    return false;
  }

  set_fat_entry_of_cluster(fs, cluster, 0xFFF);

  d.first_cluster_low = cluster;

  uint8_t *free_entry;
  // mkdir in root
  if (!strchr(path_dst + 1, '\\')) {
    uint8_t *begin =
        (uint8_t *)fs->mapping +
        fs->first_root_directory_sector * (uint32_t)fs->bpb.bytes_per_sector;
    uint8_t *end = begin + (uint32_t)fs->bpb.root_entry_count * DIRECTORY_SIZE;
    free_entry = cluster_find_free_entry(begin, end);
    if (!free_entry) {
      fprintf(stderr, "Root directory is full\n");
      return false;
    }
  } else {
    uint8_t *parent = filesystem_follow_path(fs, path_dst, true);
    if (!parent) {
      fprintf(stderr, "Parent directory does not exist\n");
      return false;
    }

    // first cluster low offset 26 length 2
    uint16_t parent_cluster = aligned_le16toh(parent + 26);

    free_entry = filesystem_directory_find_free_entry(fs, parent_cluster);
    if (!free_entry) {
      fprintf(stderr, "Parent directory is full\n");
      return false;
    }

    // last access time offset 18 length 2
    *(uint16_t *)(parent + 18) = date;
    // write time offset 22 length 2
    *(uint16_t *)(parent + 22) = time;
    // write date offset 24 length 2
    *(uint16_t *)(parent + 24) = date;
  }

  for (;;) {
    uint8_t *begin = addr_of_cluster(fs, cluster);
    uint32_t partial_read = d.file_size % fs->bytes_per_cluster;
    uint32_t to_read = fs->bytes_per_cluster - partial_read;

    uint32_t n = fread(begin + partial_read, 1, to_read, f);
    if (n == 0) {
      if (feof(f)) {
        memset(begin + partial_read, 0, fs->bytes_per_cluster - partial_read);
        fclose(f);
        break;
      } else {
        fprintf(stderr, "Problem while reading from source\n");
        fclose(f);
        return false;
      }
    }

    d.file_size += n;

    bool has_partial_read = partial_read + n != fs->bytes_per_cluster;
    if (!has_partial_read) {
      uint16_t new_cluster = find_free_cluster(fs);
      if (cluster == 0) {
        fprintf(stderr, "No free clusters\n");
        return false;
      }

      set_fat_entry_of_cluster(fs, new_cluster, 0xFFF);
      set_fat_entry_of_cluster(fs, cluster, new_cluster);
      cluster = new_cluster;
    }
  }

  directory_write(&d, free_entry);
  return true;
}

bool filesystem_del(struct filesystem *fs, char const *path) {
  if (path[0] != '\\') {
    fprintf(stderr, "Path must start with root\n");
    return false;
  }

  if (path[1] == '\0') {
    fprintf(stderr, "Root cannot be deleted\n");
    return false;
  }

  uint8_t *addr = filesystem_follow_path(fs, path, false);
  if (!addr) {
    fprintf(stderr, "Does not exist\n");
    return false;
  }

  struct directory d;
  directory_init(&d, addr);
  if (d.attribute & ATTR_DIRECTORY) {
    fprintf(stderr, "Is a directory\n");
    return false;
  } else if (d.attribute & ATTR_READ_ONLY) {
    fprintf(stderr, "Is read-only\n");
    return false;
  } else if (d.attribute & ATTR_SYSTEM) {
    fprintf(stderr, "Is a system file\n");
    return false;
  } else if (d.attribute & ATTR_VOLUME_ID) {
    fprintf(stderr, "Is volume id\n");
    return false;
  }

  // is not in root directory
  if (strchr(path + 1, '\\')) {
    uint8_t *parent = filesystem_follow_path(fs, path, true);

    struct timespec tp;
    clock_gettime(CLOCK_REALTIME, &tp);
    uint16_t time = directory_time_from_timespec(&tp);
    uint16_t date = directory_date_from_timespec(&tp);
    // last access time offset 18 length 2
    *(uint16_t *)(parent + 18) = htole16(date);
    // write time offset 22 length 2
    *(uint16_t *)(parent + 22) = htole16(time);
    // write date offset 24 length 2
    *(uint16_t *)(parent + 24) = htole16(date);
  }

  filesystem_dealloc_cluster_chain(fs, d.first_cluster_low);
  // mark as free
  addr[0] = 0xE5;
  return true;
}

static void filesystem_directory_dump_chain(struct filesystem const *fs,
                                            bool is_directory, uint16_t cluster,
                                            char const *name, size_t name_len, uint32_t *file_count, uint32_t *dir_count) {
  for (;;) {
    printf("Block %u:\t", cluster);
    fwrite(name, 1, name_len, stdout);
    putchar('\n');

    if (is_directory) {
      struct directory d;
      uint8_t *begin = addr_of_cluster(fs, cluster);
      uint8_t *end = addr_of_cluster(fs, cluster) + fs->bytes_per_cluster;
      for (; begin != end; begin += DIRECTORY_SIZE) {
        directory_init(&d, begin);
        if (d.name[0] == 0xE5 || d.name[0] == '.' || d.name[1] == '.') {
          continue;
        } else if (d.name[0] == 0x00) {
          break;
        }

        if (d.attribute & ATTR_DIRECTORY) {
          ++(*dir_count);
        } else {
          ++(*file_count);
        }

        if (d.first_cluster_low == 0) {
          continue;
        }

        char subdirectory_name[13];
        directory_name_decode(subdirectory_name, d.name);
        filesystem_directory_dump_chain(fs, d.attribute & ATTR_DIRECTORY,
                                        d.first_cluster_low, subdirectory_name,
                                        strlen(subdirectory_name), file_count, dir_count);
      }
    }

    uint16_t next_cluster = fat_entry_of_cluster(fs, cluster);
    if (next_cluster < 2 || next_cluster >= fs->count_of_clusters) {
      break;
    }

    cluster = next_cluster;
  }
}

void filesystem_dumpe2fs(struct filesystem const *fs) {
  uint16_t block_count = fs->data_sectors / fs->bpb.sectors_per_cluster;
  printf("Block count:\t%u\n", block_count);

  uint16_t free_blocks = 0;
  for (uint16_t i = 2; i <= block_count + 1; ++i) {
    if (fat_entry_of_cluster(fs, i) == 0x000) {
      ++free_blocks;
    }
  }
  printf("Free blocks:\t%u\n", free_blocks);

  printf("Block size:\t%u\n", fs->bytes_per_cluster);

  uint32_t file_count = 0;
  uint32_t directory_count = 0;

  uint8_t *root_begin =
      (uint8_t *)fs->mapping +
      fs->first_root_directory_sector * fs->bpb.bytes_per_sector;
  uint8_t *root_end = root_begin + fs->bpb.root_entry_count * DIRECTORY_SIZE;
  for (; root_begin != root_end; root_begin += DIRECTORY_SIZE) {
    struct directory d;
    directory_init(&d, root_begin);
    if (d.name[0] == 0xE5) {
      continue;
    } else if (d.name[0] == 0x00) {
      break;
    }

        if (d.attribute & ATTR_DIRECTORY) {
          ++directory_count;
        } else {
          ++file_count;
        }

        if (d.first_cluster_low == 0) {
          continue;
        }

    char subdirectory_name[13];
    directory_name_decode(subdirectory_name, d.name);
    filesystem_directory_dump_chain(fs, d.attribute & ATTR_DIRECTORY, d.first_cluster_low, subdirectory_name, strlen(subdirectory_name), &file_count, &directory_count);
  }

  printf("Directory count:\t%u\n", directory_count);
  printf("File count:\t\t%u\n", file_count);
}
