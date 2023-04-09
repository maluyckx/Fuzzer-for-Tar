#ifndef UTILS_H
#define UTILS_H

#include "constants.h"

struct test_status_t { // Struct to keep track of the status of various tests performed on the tar file
    int number_of_tries;
    int number_of_success;
    int number_or_tar_created;

    int successful_with_empty_field;
    int successful_with_non_ASCII_field;
    int successful_with_non_numeric_field;
    int successful_with_too_short_field;
    int successful_with_non_octal_field;
    int successful_with_field_cut_in_middle;
    int successful_with_field_not_terminated_null_byte;
    int successful_with_null_byte_in_the_middle;
    int success_with_no_null_bytes;
    int successful_with_special_character;
    int successful_with_negative_value;

    int name_fuzzing_success;
    int mode_fuzzing_success;
    int uid_fuzzing_success;
    int gid_fuzzing_success;
    int size_fuzzing_success;
    int mtime_fuzzing_success;
    int checksum_fuzzing_success;
    int typeflag_fuzzing_success;
    int linkname_fuzzing_success;
    int magic_fuzzing_success;
    int version_fuzzing_success;
    int uname_fuzzing_success;
    int gname_fuzzing_success;
    int end_of_file_fuzzing_success;
};

void init_test_status(struct test_status_t* ts);
void print_test_status(struct test_status_t* ts);

// for all the functions that we will use on the header, content and end of the tar
void print_header(tar_header* header);
unsigned int calculate_checksum(tar_header* entry);
void create_tar(tar_header* header, char* content, size_t content_size, char* end_bytes_buffer, size_t end_size);
void create_empty_tar(tar_header* header);
int extract(char* path);
void start_header(tar_header* header);

extern struct test_status_t test_status;

extern int update_checksum;

#endif