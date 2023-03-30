#ifndef UTILS_H
#define UTILS_H

#include "constants.h"


// for all the functions that we will use on the header, content and end of the tar
void print_header(tar_header* header);

unsigned int calculate_checksum(tar_header* entry);

void change_size(tar_header* header, size_t size);

void change_header_field(char* header_field, char* new_value, size_t size);

void create_tar(tar_header* header, char* content, size_t content_size, char* end_bytes_buffer, size_t end_size);

void create_empty_tar(tar_header* header);

int extract(char* path);

void start_header(tar_header* header);

#endif