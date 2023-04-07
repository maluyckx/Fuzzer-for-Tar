#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "utils.h"

static tar_header header; // really bad coding practice but otherwise, I would need to pass the arg to EVERY function in this project

char* path_file; // Workaround to avoid passing the variable as an argument to every function in the program TODO : find a better name lol

void fuzzing_on_precise_field(char* field_name, size_t field_size) {
    // field size is needed in the definition : https://stackoverflow.com/questions/5493281/c-sizeof-a-passed-array

    // Test 1 : Empty field
    start_header(&header);
    strncpy(field_name, "", field_size);
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_empty_field++;
    }

    // Test 2 : Non-ASCII field

    char not_ascii = 'Ω'; // warning about overflow is NORMAL, that is what we want
    start_header(&header);
    strncpy(field_name, &not_ascii, field_size); // omega : is represented in Unicode by the code point U+03A9
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_non_ASCII_field++;
    }

    // Test 3 : Non-numeric field
    char non_numeric_field[] = "https://www.youtube.com/watch?v=oLsVrshvOaI";
    start_header(&header);
    strncpy(field_name, non_numeric_field, field_size); // warning is FINE : it is NORMAL that it is too long
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_non_numeric_field++;
    }

    // Test 4 : Too short field
    srand(time(NULL));
    start_header(&header);
    for (int i = 0; i < (int) field_size - 1; i++) { // Generate "field_size - 1" random letters 
        field_name[i] = 'a' + rand() % 26;
    }
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_too_short_field++;
    }

    // Test 5 : Not octal field
    start_header(&header);
    memset(field_name, '9', field_size - 1); 
    field_name[field_size - 1] = 0;
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_non_octal_field++;
    }

    // Test 6 : Field cut in the middle
    start_header(&header);
    memset(field_name, 0, field_size);
    memset(field_name, '1', field_size / 2 );
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_field_cut_in_middle++;
    }

    // Test 7 : Field not terminated by null byte
    start_header(&header);
    memset(field_name, '5', field_size);
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_field_not_terminated_null_byte++;
    }

    // TODO : avoir plusieurs champs dans le status de test?
    // Test 8 : Null byte in the middle of the field (Part 1)
    start_header(&header);
    memset(field_name, 0, field_size);
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 9 : Null byte in the middle of the field (Part 2)
    // Set the first half of field_name to contain null bytes and the second half to '0'
    start_header(&header);
    memset(field_name, 0, field_size);
    memset(field_name, '0', field_size / 2);
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 10 : Null byte in the middle of the field (Part 3)
    // Set field_name to contain '0' except for the last byte which is set to a null byte
    start_header(&header);
    memset(field_name, '0', field_size - 1);
    field_name[field_size - 1] = 0;
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
        test_status.successful_with_null_byte_in_the_middle++;
    }

    // Test 11 : Null byte in the middle of the field (Part 4)
    // Set all bytes of field_name to null except for the last byte which is set to '0'
    start_header(&header);
    memset(field_name, 0, field_size - 1);
    field_name[field_size - 1] = '0';
    create_empty_tar(&header);
    if (extract(path_file) == 1) {
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
    if (extract(path_file) == 1) {
        test_status.success_with_no_null_bytes++;
    }

    // Test 12 : Check for special characters, whitespace or control characters
    char special_chars[] = { '\"', '\'', ' ', '\t', '\r', '\n', '\v', '\f' };
    for (int i = 0; i < (int) sizeof(special_chars); i++) {
        start_header(&header);
        memset(field_name, special_chars[i], field_size);
        field_name[field_size - 1] = 0;
        create_empty_tar(&header);
        if (extract(path_file) == 1) {
            test_status.successful_with_special_character++;
        }
    }

    // TODO : Vincent
    // 2x 512 bytes filled with 0s should be present but not mandatory
}

void name_fuzzing(){

    printf("\n~~~ NAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.name, sizeof(header.name));

    test_status.name_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ MODE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

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
        extract(path_file);
    }

    // The code below tries to brute-force every possible value from 0000 to 9999.
    // We decided to not keep it since it did not bring any good result and it was taking too much time.
    /*
    for (int i = 0; i < 10000; i++) {
        char mode[sizeof(header.mode)];
        start_header(&header);
        snprintf(mode, sizeof(header.mode), "%o", i);
        strncpy(header.mode, mode, sizeof(header.mode));
        create_empty_tar(&header);
        extract(path_file);
    }
    */

    test_status.mode_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ MODE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

void uid_fuzzing(){

    printf("\n~~~ UID Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.uid, sizeof(header.uid));

    test_status.uid_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ UID Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

void gid_fuzzing(){
    
    printf("\n~~~ GID Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.gid, sizeof(header.gid));

    test_status.gid_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ GID Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

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
        possible_size[i] = rand() % HEADER_LENGTH;
    }

    for (int i = 0; i < number_of_try; i++) { // TODO comprendre pourquoi ça marche aussi bien wtf
        start_header(&header);
        char end_data[HEADER_LENGTH];
        memset(end_data, 0, HEADER_LENGTH);
        snprintf(header.size, sizeof(header.size), "%o", possible_size[i]);
        create_tar(&header, content_header, content_header_size, end_data, HEADER_LENGTH);
        extract(path_file);
    }

    test_status.size_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ SIZE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void create_header_with_time(time_t time) {
    char time_string[sizeof(header.mtime)];
    start_header(&header);
    snprintf(time_string, sizeof(header.mtime), "%lo", time);
    strncpy(header.mtime, time_string, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_file);
}

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


void chksum_fuzzing(){
    printf("\n~~~ CHECKSUM Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.chksum, sizeof(header.chksum));

    test_status.checksum_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ CHECKSUM Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void typeflag_fuzzing(){

    printf("\n~~~ TYPEFLAG Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    // Brute-force every possible value from 0 to 255, possible since typeflag is a single-byte character
    for (int i = 0; i < 256; i++){
        start_header(&header);
        header.typeflag = (char) i;
        create_empty_tar(&header);
        extract(path_file);
    }

    // Test with negative values
    start_header(&header);
    header.typeflag = -1;
    create_empty_tar(&header);
    extract(path_file);

    // Test with non-ASCII characters
    start_header(&header);
    header.typeflag = '日'; // warning about overflow is NORMAL, that is what we want
    create_empty_tar(&header);
    extract(path_file);


    test_status.typeflag_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ TYPEFLAG Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void linkname_fuzzing(){
    printf("\n~~~ LINKNAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.linkname, sizeof(header.linkname));
    
    test_status.linkname_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ LINKNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void magic_fuzzing(){

    printf("\n~~~ MAGIC Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.magic, sizeof(header.magic));

    test_status.magic_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ MAGIC Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

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
            extract(path_file);
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
            extract(path_file);
        }
    }
 
    test_status.version_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ VERSION Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void uname_fuzzing(){

    printf("\n~~~ UNAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.uname, sizeof(header.uname));

    test_status.uname_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ UNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");

}

void gname_fuzzing(){

    printf("\n~~~ GNAME Header Fuzzing ~~~\n");
    int previous_success = test_status.number_of_success;

    fuzzing_on_precise_field(header.gname, sizeof(header.gname));

    test_status.gname_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ GNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

void end_of_file_fuzzing() {

    printf("\n~~~ End of File Fuzzing ~~~\n");
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
        extract(path_file);

        start_header(&header);
        snprintf(header.size, sizeof(header.size), "%011o", content_header_size);
        create_tar(&header, content_header, content_header_size, end_data, end_data_sizes[i]); // Create a tar file with the dummy text
        extract(path_file);
        i++;
    }


    test_status.end_of_file_fuzzing_success += test_status.number_of_success - previous_success;
    printf("\n~~~ End of File Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}


void remove_files() {
    // https://www.tecmint.com/delete-all-files-in-directory-except-one-few-file-extensions/

    system("find . ! -name '.gitignore' ! -name 'constants.h' ! -name 'extractor' ! -name 'extractor_v2' ! -name 'fuzzer' ! -name 'fuzzer_statement.pdf' ! -name 'help.c' ! -name 'main.c' ! -name 'Makefile' ! -name 'README.md' ! -name 'rm_success.sh' ! -name 'utils.c' ! -name 'utils.h' ! -name 'success_*' ! -path './.' ! -path './..' ! -path './.git' ! -path './.idea' ! -path './.git/*' ! -path './.idea/*' -delete"); 
    system("./rm_success.sh");
}


void fuzzing(){
    init_test_status(&test_status);

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

    print_test_status(&test_status);

    remove_files();
}


int main(int argc, char* argv[]){
    if (argc != 2) {
        printf("Invalid number of arguments.\n");
        printf("This is a valid command : ./fuzzer <path to the tar extractor>");
        printf("Example : ./fuzzer ./extractor");
        return -1;
    }
    path_file = argv[1];
    fuzzing(); 
}
