#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"

struct test_status_t test_status;

/**
 * @brief Initiates the test_status_t struct with all values to 0.
 * 
 * @param ts Pointer to the test_status_t struct to print.
 */
void init_test_status(struct test_status_t *ts) {
    memset(ts, 0, sizeof(int)*28);
}

/**
 * @brief Prints the test status struct to stdout in a user-friendly format, providing a global overview of the program's execution.
 *        The output provides insight into which fields were fuzzed successfully and which were not.
 *        This function is useful for debugging and assessing the quality of the test cases.
 * @param ts Pointer to the test_status_t struct to print.
 */
void print_test_status(struct test_status_t *ts) {
    printf("\n\nTest status\n");
    printf("Number of trials : %d\n", ts->number_of_tries);
    printf("Number of success: %d\n\n", ts->number_of_success);
    printf("Success with \n");
    printf("\t     Empty field                       : %d\n", ts->successful_with_empty_field);
    printf("\t     non ASCII field                   : %d\n", ts->successful_with_non_ASCII_field);
    printf("\t     non numeric field                 : %d\n", ts->successful_with_non_numeric_field);
    printf("\t     too short field                   : %d\n", ts->successful_with_too_short_field);
    printf("\t     non octal field                   : %d\n", ts->successful_with_non_octal_field);
    printf("\t     field cut in middle               : %d\n", ts->successful_with_field_cut_in_middle);
    printf("\t     field null terminated             : %d\n", ts->successful_with_field_not_terminated_null_byte);
    printf("\t     field with null byte in the middle: %d\n", ts->successful_with_null_byte_in_the_middle);
    printf("\t     field with no null bytes          : %d\n", ts->success_with_no_null_bytes);
    printf("\t     field with special character      : %d\n", ts->successful_with_special_character);
    printf("\t     field with negative value         : %d\n\n", ts->successful_with_negative_value);
    printf("Success on \n");
    printf("\t   name field       : %d\n", ts->name_fuzzing_success);
    printf("\t   mode field       : %d\n", ts->mode_fuzzing_success);
    printf("\t   uid field        : %d\n", ts->uid_fuzzing_success);
    printf("\t   gid field        : %d\n", ts->gid_fuzzing_success);
    printf("\t   size field       : %d\n", ts->size_fuzzing_success);
    printf("\t   mtime field      : %d\n", ts->mtime_fuzzing_success);
    printf("\t   checksum field   : %d\n", ts->checksum_fuzzing_success);
    printf("\t   typeflag field   : %d\n", ts->typeflag_fuzzing_success);
    printf("\t   linkname field   : %d\n", ts->linkname_fuzzing_success);
    printf("\t   magic field      : %d\n", ts->magic_fuzzing_success);
    printf("\t   version field    : %d\n", ts->version_fuzzing_success);
    printf("\t   uname field      : %d\n", ts->uname_fuzzing_success);
    printf("\t   gname field      : %d\n", ts->gname_fuzzing_success);
    printf("\t   end of file field: %d\n\n", ts->end_of_file_fuzzing_success);
}

/**
 * @brief Computes the checksum for a tar header and encode it on the header
 *        This function was taken from the 'help.c' file that was provided.
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_header* entry){ // PROF FUNCTION
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', sizeof(entry->chksum));

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < HEADER_LENGTH; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}


/**
 * @brief Launches another executable given as argument,
 *        parses its output and check whether or not it matches "*** The program has crashed ***".
 *        This function was taken from the 'help.c' file that was provided.
 * @param path the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 */
int extract(char* path){ // PROF FUNCTION
    test_status.number_of_tries++;

    int rv = 0;
    char cmd[51];
    strncpy(cmd, path, 25);
    cmd[26] = '\0';
    strncat(cmd, " archive.tar", 25);
    char buf[33];
    FILE *fp;
    if ((fp = popen(cmd, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }
    if(fgets(buf, 33, fp) == NULL) {
        printf("No output\n");
        goto finally;
    }
    if(strncmp(buf, "*** The program has crashed ***\n", 33)) {
        printf("Not the crash message\n");
        goto finally;
    } else {
        printf("Crash message\n");
        rv = 1;
        test_status.number_of_success++;

        char success_name[200];
        snprintf(success_name, sizeof(success_name), "success_%d.tar", test_status.number_of_success);

        int result = rename("archive.tar", success_name);
        if (result == 0) {
            printf("File moved successfully!\n");
        } else {
            printf("Failed to move file.\n");
        }

        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}

/**
 * @brief Initializes a tar header with default values and sets the necessary fields,
 *        such as the archive name, mode, uid, gid, size, etc to prepare it for the creation of a tar archive.
 *        The function also calculates the header checksum after setting all the header fields.
 *
 * @param header The tar header struct to be initialized.
 */
void start_header(tar_header* header) {

    char archive_name[100];
    snprintf(archive_name, sizeof(archive_name), "archive_%d.tar", test_status.number_or_tar_created++);
    char linkname[100] = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    char full_zero[8] = "0000000";

    memset(header, 0, sizeof(tar_header));

    snprintf(header->name, sizeof(header->name), "%s", archive_name);
    snprintf(header->mode, sizeof(header->mode), "07777"); // all perms (based on constants.h)
    snprintf(header->uid, sizeof(header->uid),"%s", full_zero);
    snprintf(header->gid, sizeof(header->gid),"%s", full_zero);
    snprintf(header->size, sizeof(header->size), "%011o", 0); // size needs to be in octal
    snprintf(header->mtime, sizeof(header->mtime), "%011lo", time(NULL)); // set modification time to current time in octal format
    //checksum at the end (need all other fields before calculating the checksum)
    header->typeflag = REGTYPE;
    snprintf(header->linkname, sizeof(header->linkname), "%s", linkname);
    snprintf(header->magic, sizeof(header->magic), TMAGIC);
    snprintf(header->version, sizeof(header->version) + 1,  TVERSION); //  '+ 1' is needed because 'no null'
    snprintf(header->uname, sizeof(header->uname), "Z3US");
    snprintf(header->gname, sizeof(header->gname), "Z3US");
    snprintf(header->devmajor, sizeof(header->devmajor),"%s", full_zero);
    snprintf(header->devminor, sizeof(header->devminor),"%s", full_zero);
    // might require prefixe and padding at some point, not so sure tbh
    calculate_checksum(header);
}

/**
 * @brief Create a tar archive and write it to disk.
 * 
 * @param header The header of the tar archive to create.
 * @param content_header A pointer to the content to write to the archive.
 * @param content_header_size The size of the content to write.
 * @param end_bytes_buffer A buffer containing end-of-archive null blocks.
 * @param end_size The size of the end_bytes_buffer.
 */
void create_tar(tar_header* header, char* content_header, size_t content_header_size, char* end_data, size_t end_size) {
    calculate_checksum(header);
    FILE *fp = fopen("archive.tar", "wb");
    if (fp == NULL) {
        perror("Error opening file");
        //exit(EXIT_FAILURE);
    }

    if (fwrite(header, sizeof(tar_header), 1, fp) != 1) {
        perror("Error writing header");
        fclose(fp);
        //exit(EXIT_FAILURE);
    }
    if (content_header_size > 0)
        if (fwrite(content_header, content_header_size, 1, fp) != 1) {
            perror("Error writing content");
            fclose(fp);
            //exit(EXIT_FAILURE);
        }
    if (end_size > 0){
        if (fwrite(end_data, end_size, 1, fp) != 1) {
            perror("Error writing end bytes");
            fclose(fp);
            //exit(EXIT_FAILURE);
        }
    }
    if (fclose(fp) != 0) {
        perror("Error closing file");
        //exit(EXIT_FAILURE);
    }
}

/**
 * @brief Create an empty tar archive.
 *        This function creates an empty tar archive with the given header by calling
 *        the create_tar function with a NULL data buffer and zero data length.
 * 
 * @param header A pointer to the header of the tar archive to create.
 */
void create_empty_tar(tar_header* header) {
    char end_data[END_BYTES];
    memset(end_data, 0, END_BYTES);
    create_tar(header, NULL, 0, end_data, END_BYTES);
}


/**
 * @brief Prints the contents of a tar_header struct. Used for debug purposes.
 * 
 * @param header Pointer to a tar_header struct to print.
 */
void print_header(tar_header* header) {
    printf("-----Header start-----\n");
    printf("Name:      %s\n", header->name);
    printf("Mode:      %s\n", header->mode);
    printf("UID:       %s\n", header->uid);
    printf("GID:       %s\n", header->gid);
    printf("Size:      %s\n", header->size);
    printf("Mtime:     %s\n", header->mtime);
    printf("Chksum:    %s\n", header->chksum);
    printf("Typeflag:  %c\n", header->typeflag);
    printf("Linkname:  %s\n", header->linkname);
    printf("Magic:     %s\n", header->magic);
    printf("Version:   %s\n", header->version);
    printf("Uname:     %s\n", header->uname);
    printf("Gname:     %s\n", header->gname);
    printf("Devmajor:  %s\n", header->devmajor);
    printf("Devminor:  %s\n", header->devminor);
    printf("Prefix:    %s\n", header->prefix);
    printf("Padding:   %s\n", header->padding);
    printf("-----Header end-----\n");
}
