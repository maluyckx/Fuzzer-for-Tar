#ifndef UTILS_H
#define UTILS_H

#include "constants.h"


// for all the functions that we will use on the header, content and end of the tar
void print_header(tar_header* header);

unsigned int calculate_checksum(tar_header* entry);


int extract(char* path);

void start_header(tar_header* header);

#endif