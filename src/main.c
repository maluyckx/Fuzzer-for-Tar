#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "utils.h"

static tar_header header; // really bad coding practice but otherwise, I would need to pass the arg to EVERY function in this project

char* path_extractor; // Workaround to avoid passing the variable as an argument to every function in the program



/**
 * @brief Removes all files in the current directory except for the relevant files and directories.
 */
void remove_files() {
    // https://www.tecmint.com/delete-all-files-in-directory-except-one-few-file-extensions/

    // To add files, use the "! -name" syntax
    // Example : ! -name '<name_of_file_that_cannot_be_deleted>'

    // To add directories, use the "! -path" syntax
    // Example : ! -path './<directory>' ! -path './<directory>/*' 

    system("find . ! -name '.gitignore' ! -name 'constants.h' ! -name 'extractor' ! -name 'extractor_v2' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'main.c' ! -name 'Makefile' ! -name 'README.md' ! -name 'rm_success.sh' ! -name 'utils.c' ! -name 'utils.h' ! -name 'success_*' ! -path './.' ! -path './..' ! -path './src' ! -path './src/*' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete"); 
    //system("./rm_success.sh");
}


/**
 * @brief This function performs fuzz testing on a given field by applying various test cases to ensure it can handle different scenarios.
 *        For each test case, the function generates a tar file using the field, extracts it, and checks if the extraction was successful.
 *        If the extraction was successful, the corresponding test case is marked as passed in the test_status object.
 * 
 * @param field_name Pointer to the field to be tested. 
 * @param field_size Size of the field. 
 */
void fuzzing_on_precise_field(char* field_name, size_t field_size) {
    // field size is needed in the definition : https://stackoverflow.com/questions/5493281/c-sizeof-a-passed-array

    /* Every test has this form :
        1) Reset the header to the default values;
        2) Make some changes in the field that you are testing;
        3) Create the corresponding tar (with the changes that you just made);
        4) Extract the tar and verify if it crashes.    
    */


    // Test 1 : Empty field
    start_header(&header);
    strncpy(field_name, "", field_size);
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_empty_field++;
    }

    // Test 2 : Non-ASCII field
    char not_ascii = 'Ω'; // warning about overflow is NORMAL, that is what we want
    start_header(&header);
    strncpy(field_name, &not_ascii, field_size); // omega : is represented in Unicode by the code point U+03A9
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_non_ASCII_field++;
    }

    // Test 3 : Non-numeric field
    char non_numeric_field[] = "https://www.youtube.com/watch?v=oLsVrshvOaI";
    start_header(&header);
    strncpy(field_name, non_numeric_field, field_size); // warning is FINE : it is NORMAL that it is too long
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_non_numeric_field++;
    }

    // Test 4 : Too short field
    srand(time(NULL));
    start_header(&header);
    for (int i = 0; i < (int) field_size - 1; i++) { // Generate "field_size - 1" random letters 
        field_name[i] = 'a' + rand() % 26;
    }
    field_name[field_size] = 0;
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_too_short_field++;
    }

    // Test 5 : Not octal field
    start_header(&header);
    memset(field_name, '9', field_size - 1); 
    field_name[field_size - 1] = 0;
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_non_octal_field++;
    }

    // Test 6 : Field cut in the middle
    start_header(&header);
    memset(field_name, 0, field_size / 2);
    memset(&field_name[field_size / 2], '1', field_size / 2);
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_field_cut_in_middle++;
    }

    // Test 7 : Field not terminated by null byte
    start_header(&header);
    memset(field_name, '5', field_size);
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_field_not_terminated_null_byte++;
    }

    // Test 8 : Null byte in the middle of the field (Part 1)
    start_header(&header);
    memset(field_name, 0, field_size);
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 9 : Null byte in the middle of the field (Part 2)
    // Set the first half of field_name to contain null bytes and the second half to '0'
    start_header(&header);
    memset(field_name, 0, field_size / 2);
    memset(&field_name[field_size / 2], '0', field_size / 2);
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 10 : Null byte in the middle of the field (Part 3)
    // Set field_name to contain '0' except for the last byte which is set to a null byte
    start_header(&header);
    memset(field_name, '0', field_size - 1);
    field_name[field_size - 1] = 0;
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 11 : Null byte in the middle of the field (Part 4)
    // Set all bytes of field_name to null except for the last byte which is set to '0'
    start_header(&header);
    memset(field_name, 0, field_size - 1);
    field_name[field_size - 1] = '0';
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 11.5 (lazy to change following number)
    // Remove all null bytes and replace them by spaces (' ')
    start_header(&header);
    size_t first_term = strnlen(field_name, field_size);

    if (first_term < field_size) {
        memset(field_name + first_term, ' ', field_size - first_term); // replace '\0' by ' '
    }
    create_empty_tar(&header);
    if (extract(path_extractor) == 1) {
        test_status.success_with_no_null_bytes++;
    }

    // Test 12 : Check for special characters, whitespace or control characters (see ASCII link in README)
    char special_chars[] = { '\"', '\'', ' ', '\t', '\r', '\n', '\v', '\f', '\b'};
    for (int i = 0; i < (int) sizeof(special_chars); i++) {
        start_header(&header);
        memset(field_name, special_chars[i], field_size);
        field_name[field_size - 1] = 0;
        create_empty_tar(&header);
        if (extract(path_extractor) == 1) {
            test_status.successful_with_special_character++;
        }
    }
    /*
    // Test 12.5 : Control characters
    start_header(&header);
    for (int c = 0; c <= 40; c++) {
        memset(field_name, c, 1);
        create_empty_tar(&header);
        if (extract(path_extractor) == 1) {
            test_status.successful_with_special_character++;
        }
    }
    */

    // Test 13 : Negative value
    start_header(&header);
    snprintf(field_name, field_size, "%d", INT_MIN);
    create_empty_tar(&header);
    extract(path_extractor);
    if (extract(path_extractor) == 1) {
        test_status.successful_with_negative_value++;
    }
}

/**
 * @brief Perform general fuzzing on the "name" field of the tar header.
 * 
 */
void name_fuzzing(){

    printf("\n~~~ NAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.name, sizeof(header.name));

    test_status.name_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ NAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

/**
 * @brief Perform general fuzzing on the "mode" field of the tar header.
 *        It iterates over the possible mode values defined in "constants.h"
 * 
 */
void mode_fuzzing(){

    printf("\n~~~ MODE Header Fuzzing ~~~\n");
    int modes[] = {TSUID, TSGID, TSVTX, TUREAD, TUWRITE, TUEXEC, TGREAD, TGWRITE, TGEXEC, TOREAD, TOWRITE, TOEXEC}; // from constants.h
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.mode, sizeof(header.mode));

    // fuzzing all possibles mode
    for (int i = 0; i < (int) sizeof(modes); i++){
        char mode[sizeof(header.mode)];
        start_header(&header);
        snprintf(mode, sizeof(header.mode), "%o", modes[i]);
        strncpy(header.mode, mode, sizeof(header.mode));
        create_empty_tar(&header);
        extract(path_extractor);
    }

    // The code below tries to brute-force every possible value from 0000 to 9999.
    // We decided to not keep it since it did not bring any good result and it was taking a lot of time.
    /*
    for (int i = 0; i < 10000; i++) {
        char mode[sizeof(header.mode)];
        start_header(&header);
        snprintf(mode, sizeof(header.mode), "%o", i);
        strncpy(header.mode, mode, sizeof(header.mode));
        create_empty_tar(&header);
        extract(path_extractor);
    }
    */

    test_status.mode_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ MODE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

/**
 * @brief Perform general fuzzing on the "uid" field of the tar header.
 * 
 */
void uid_fuzzing(){

    printf("\n~~~ UID Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.uid, sizeof(header.uid));

    test_status.uid_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ UID Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}
/**
 * @brief Perform general fuzzing on the "gid" field of the tar header.
 * 
 */
void gid_fuzzing(){
    
    printf("\n~~~ GID Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.gid, sizeof(header.gid));

    test_status.gid_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ GID Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}


/**
 * @brief Perform general fuzzing on the "size" field of the tar header.
 *        This function generates random values for the "size" field and creates headers with those values.
 */
void size_fuzzing(){

    printf("\n~~~ SIZE Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.size, sizeof(header.size));

    char content_header[] = "https://www.youtube.com/watch?v=ik3B-Kb7QBk";
    int content_header_size = sizeof(content_header); 

    int number_of_try = 10;
    int possible_size[number_of_try];
    srand(time(NULL));
    for(int i = 0; i < number_of_try; i++){
        possible_size[i] = rand() % BLOCK_SIZE;
    }

    for (int i = 0; i < number_of_try; i++) {
        start_header(&header);
        char end_data[BLOCK_SIZE];
        memset(end_data, 0, BLOCK_SIZE);
        snprintf(header.size, sizeof(header.size), "%o", possible_size[i]);
        create_tar(&header, content_header, content_header_size, end_data, BLOCK_SIZE);
        extract(path_extractor);
    }

    // test negative size
    start_header(&header);
    snprintf(header.size, sizeof(header.size), "%d", INT_MIN);
    char end_data[BLOCK_SIZE];
    memset(end_data, 0, BLOCK_SIZE);
    create_tar(&header, content_header, content_header_size, end_data, BLOCK_SIZE);
    if (extract(path_extractor) == 1)
        test_status.successful_with_negative_value++;

    test_status.size_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ SIZE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}


/**
 * @brief Creates a tar header with the specified time value by converting the time
 *        into a string and copying it into the 'mtime' field of the header.
 *        Then creates an empty tar file with the header and extracts it to the filesystem.
 * 
 * @param time The time value to be set in the header.
 */
void create_header_with_time(time_t time) {
    char time_string[sizeof(header.mtime)];
    start_header(&header);
    snprintf(time_string, sizeof(header.mtime), "%lo", time);
    strncpy(header.mtime, time_string, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_extractor);
}

/**
 * @brief Perform general fuzzing on the "mtime" field of the tar header.
 *        The function tests various scenarios :
 *        - Test with the minimum and maximum value for int and long long int.
 *        - Test with various time intervals such as 5 minutes before/after 1970, 1 year ago,
 *          current time and 1 month in the future.
 */
void mtime_fuzzing() {
    printf("\n~~~ MTIME Header Fuzzing ~~~\n");

    int previous_success = test_status.number_of_success;
    time_t now = time(NULL);

    fuzzing_on_precise_field(header.mtime, sizeof(header.mtime));

    // Test with the minimum value for int
    create_header_with_time(INT_MIN);

    // Test with date 5 minutes before 1970
    create_header_with_time(-300);

    // Test with date 5 minutes after 1970
    create_header_with_time(300);

    // Test with date 1 year in the past
    time_t one_year_ago = now - (365 * 24 * 60 * 60);
    create_header_with_time(one_year_ago);

    // Test with current date
    create_header_with_time(now);

    // Test with date 1 month in the future
    time_t one_month_from_now = now + (30 * 24 * 60 * 60);
    create_header_with_time(one_month_from_now);

    // Test with the maximum value for an int
    time_t max_int_time = now + INT_MAX;
    create_header_with_time(max_int_time);

    // Test with the maximum value for a long long int
    time_t max_long_long_time = now + LLONG_MAX;
    create_header_with_time(max_long_long_time);

    test_status.mtime_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ MTIME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

/**
 * @brief Perform general fuzzing on the "chksum" field of the tar header.
 */
void chksum_fuzzing(){
    printf("\n~~~ CHECKSUM Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;
    update_checksum = 0; // interrupts the process of having the right checksum for the header

    fuzzing_on_precise_field(header.chksum, sizeof(header.chksum));

    char content_header[] = "https://www.youtube.com/shorts/AcOQeKPX-Hs"; // dummy text
    int content_header_size = sizeof(content_header);
    char end_data[BLOCK_SIZE];
    start_header(&header);
    memset(&header.chksum, 0, 1);
    create_tar(&header, content_header, content_header_size, end_data, BLOCK_SIZE);
    extract(path_extractor);

    update_checksum = 1;
    test_status.checksum_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ CHECKSUM Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}


/**
 * @brief Brute-force every possible value of the "typeflag" field, since it is only one byte.
 *        In addition to positive values, we also try negative values and non-ASCII characters.
 */
void typeflag_fuzzing(){

    printf("\n~~~ TYPEFLAG Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    // Brute-force every possible value from 0 to 255, possible since typeflag is a single-byte character
    for (int i = 0; i < 256; i++){
        start_header(&header);
        header.typeflag = (char) i;
        create_empty_tar(&header);
        extract(path_extractor);
    }

    // Test with negative values
    start_header(&header);
    header.typeflag = -1;
    create_empty_tar(&header);
    extract(path_extractor);

    // Test with non-ASCII characters
    start_header(&header);
    header.typeflag = '日'; // warning about overflow is NORMAL, that is what we want
    create_empty_tar(&header);
    extract(path_extractor);

    test_status.typeflag_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ TYPEFLAG Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}


/**
 * @brief Perform general fuzzing on the "linkname" field of the tar header.
 */
void linkname_fuzzing(){
    printf("\n~~~ LINKNAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.linkname, sizeof(header.linkname));
    
    test_status.linkname_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ LINKNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

/**
 * @brief Perform general fuzzing on the "magic" field of the tar header.
 */
void magic_fuzzing(){

    printf("\n~~~ MAGIC Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.magic, sizeof(header.magic));

    test_status.magic_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ MAGIC Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

/**
 * @brief Perform general fuzzing on the "version" field of the tar header.
 *        Additionally, since the field is only 2 bytes long and in octal format,
 *        we brute-force every possible value and try negative values too. 
 */
void version_fuzzing(){

    printf("\n~~~ VERSION Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.version, sizeof(header.version));

    // The 'version' field is only 2 bytes long and in octal format, so we can brute-force every possible value
    char octal[3] = {'0', '0', '\0'};
        
    for (int i = 0; i < 8; i++) {
        octal[0] = i + '0';
        for (int j = 0; j < 8; j++) {
            octal[1] = j + '0';

            start_header(&header);
            strncpy(header.version, octal, sizeof(header.version));
            create_empty_tar(&header);
            extract(path_extractor);
        }
    }

    // Also try negative values for the octal representation of 'version'
    for (int i = -1; i >= -8; i--) {
        octal[0] = i + '0';
        for (int j = -1; j >= -8; j--) {
            octal[1] = j + '0';

            start_header(&header);
            strncpy(header.version, octal, sizeof(header.version));
            create_empty_tar(&header);
            extract(path_extractor);
        }
    }
 
    test_status.version_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ VERSION Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

/**
 * @brief Perform general fuzzing on the "uname" field of the tar header.
 * 
 */
void uname_fuzzing(){

    printf("\n~~~ UNAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.uname, sizeof(header.uname));

    test_status.uname_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ UNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");

}

/**
 * @brief Perform general fuzzing on the "gname" field of the tar header.
 * 
 */
void gname_fuzzing(){

    printf("\n~~~ GNAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.gname, sizeof(header.gname));

    test_status.gname_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ GNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

/**
 * @brief This function performs fuzzing tests on the size of the data at the end of a tar file. 
 *        It generates tar files with varying sizes of end data and extracts them to verify that the program
 *        can handle such files.
 */
void end_of_file_fuzzing() {

    printf("\n~~~ END OF FILE Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    int end_data_sizes[] = {0, 1, END_BYTES / 4, END_BYTES / 2 , END_BYTES - 1, END_BYTES, END_BYTES + 1, END_BYTES * 2, END_BYTES * 4};
    int sizeof_array = sizeof(end_data_sizes) / sizeof(int);

    char end_data[end_data_sizes[sizeof_array - 1]];
    memset(end_data, 0, end_data_sizes[sizeof_array - 1]);
    char content_header[] = "https://www.youtube.com/watch?v=xvFZjo5PgG0"; // dummy text
    int content_header_size = sizeof(content_header);

    int i = 0;
    while (i < sizeof_array) {
        start_header(&header);
        create_tar(&header, NULL, 0, end_data, end_data_sizes[i]); // Create a tar file with no file content
        extract(path_extractor);

        start_header(&header);
        snprintf(header.size, sizeof(header.size), "%o", content_header_size);
        create_tar(&header, content_header, content_header_size, end_data, end_data_sizes[i]); // Create a tar file with the dummy text
        extract(path_extractor);
        i++;
    }

    test_status.end_of_file_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ END OF FILE Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}


/**
 * @brief performs fuzz testing on various tar fields by calling specific functions for each field.
 * 
 * @param argc 
 * @param argv  
 */
int main(int argc, char* argv[]){
    if (argc != 2) {
        printf("Invalid number of arguments.\n");
        printf("This is a valid command : ./fuzzer <path to the tar extractor>");
        printf("Example : ./fuzzer ./src/extractor");
        return -1;
    }
    path_extractor = argv[1];

    init_test_status(&test_status);

    printf("\n~~~ STARTING Fuzzing ~~~\n");
    name_fuzzing();
    mode_fuzzing();
    uid_fuzzing();
    gid_fuzzing();
    size_fuzzing();
    mtime_fuzzing();
    chksum_fuzzing();
    typeflag_fuzzing();
    linkname_fuzzing();
    magic_fuzzing();
    version_fuzzing();
    uname_fuzzing();
    gname_fuzzing();
    end_of_file_fuzzing();
    printf("\n~~~ Fuzzing COMPLETED SUCCESSFULLY ~~~\n");

    print_test_status(&test_status);

    remove_files();
}
