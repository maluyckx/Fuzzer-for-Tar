#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"


static tar_header header; // really bad coding practice but otherwise, I would need to pass the arg to EVERY function in this project

char* path_file; // Workaround to avoid passing the variable as an argument to every function in the program TODO : find a better name lol

void fuzzing_on_precise_field(char* field_name, size_t field_size) {
    // field size is needed : https://stackoverflow.com/questions/5493281/c-sizeof-a-passed-array

    printf("size of the field: %ld\n", field_size);

    // Test 1 : Empty field
    start_header(&header);
    change_header_field(field_name, "", field_size);
    create_empty_tar(&header);
    extract(path_file);

    // Test 2 : Non-ASCII field
    start_header(&header);
    change_header_field(field_name, 'Ω', field_size); // omega : is represented in Unicode by the code point U+03A9
    create_empty_tar(&header);
    extract(path_file);

    // Test 3 : Non-numeric field
    start_header(&header);
    change_header_field(field_name, 'https://www.youtube.com/watch?v=oLsVrshvOaI', field_size); // warning is FINE : it is NORMAL that it is too long
    create_empty_tar(&header);
    extract(path_file);

    // Test 4 : Too short field


    // Test 5 : Not octal field
    start_header(&header);
    memset(field_name, '9', field_size - 1); // like we say in french : 'simple et efficace' 
    field_name[field_size - 1] = 0;
    create_empty_tar(&header);
    extract(path_file);


    // Test 6 : Field cut in the middle
    start_header(&header);
    memset(field_name, 0, field_size);
    memset(field_name, '1', field_size / 2 );
    create_empty_tar(&header);
    extract(path_file);

    // Test 7 : Field not terminated by null byte
    start_header(&header);
    memset(field_name, '5', field_size);
    create_empty_tar(&header);
    extract(path_file);

    // TODO : etre plus descriptif que 'part 1'
    // Test 8 : Null byte in the middle of the field (Part 1)
    start_header(&header);
    memset(field_name, 0, field_size);
    create_empty_tar(&header);
    extract(path_file);

    // Test 9 : Null byte in the middle of the field (Part 2)
    start_header(&header);
    memset(field_name, 0, field_size);
    memset(field_name, '0', field_size / 2);
    create_empty_tar(&header);
    extract(path_file);

    // Test 11 : Null byte in the middle of the field (Part 3)
    start_header(&header);
    memset(field_name, '0', field_size - 1);
    field_name[field_size - 1] = 0;
    create_empty_tar(&header);
    extract(path_file);

    // Test 11 : Null byte in the middle of the field (Part 4)
    start_header(&header);
    memset(field_name, 0, field_size - 1);
    field_name[field_size - 1] = '0';
    create_empty_tar(&header);
    extract(path_file);

    // Test 12 : Check for special characters, whitespace or control characters | TODO verify that it is correct, it smells fishy
    char special_chars[] = { '\"', '\'', ' ', '\t', '\r', '\n', '\v', '\f' };
    for (int i = 0; i < (int) sizeof(special_chars); i++) { // Roggeman ne me tuera pas car on est en C HEHEHEHEHE
        start_header(&header);
        memset(field_name, special_chars[i], field_size);
        field_name[field_size - 1] = 0;
        create_empty_tar(&header);
        extract(path_file);
    }

    // TODO
    // modify order or placement of header parts


    // Vincent
    // end-of-file marker
    // 2x 512 bytes filled with 0s should be present but not mandatory
    // should issue a warning if not found
}

void remove_null_terminators(char* field_name) { 
    size_t field_size = sizeof(field_name);

    // find first terminator:
    size_t first_term = field_size;
    for (size_t i=0; i<field_size; i++) {
        if (field_name[i] == '\0') {
            first_term = i;
            break;
        }
    }

    memset(field_name+first_term, ' ', field_size - first_term); // replace '\0' by ' '
    create_empty_tar(&header);
    extract(path_file);
}



void name_fuzzing(){

    printf("\n~~~ NAME Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.name, sizeof(header.name));


    printf("\n~~~ MODE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void mode_fuzzing(){

    printf("\n~~~ MODE Header Fuzzing ~~~\n");
    int modes[] = {TSUID, TSGID, TSVTX, TUREAD, TUWRITE, TUEXEC, TGREAD, TGWRITE, TGEXEC, TOREAD, TOWRITE, TOEXEC}; // from constants.h

    fuzzing_on_precise_field(header.mode, sizeof(header.mode));

    // fuzzing all possibles mode
    for (int i = 0; i < (int) sizeof(modes); i++){
        char mode[sizeof(header.mode)];
        start_header(&header);
        snprintf(mode, sizeof(header.mode), "%07o", modes[i]); // TODO : verify why %070
        change_header_field(header.mode, mode, sizeof(header.mode));
        create_empty_tar(&header);
        extract(path_file);
    }

    // TODO : maybe try other values ?

    printf("\n~~~ MODE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

void uid_fuzzing(){

    printf("\n~~~ UID Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.uid, sizeof(header.uid));

    printf("\n~~~ UID Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

void gid_fuzzing(){
    
    printf("\n~~~ GID Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.gid, sizeof(header.gid));

    printf("\n~~~ GID Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void size_fuzzing(){

    printf("\n~~~ SIZE Header Fuzzing ~~~\n");


    fuzzing_on_precise_field(header.size, sizeof(header.size));

    // TODO : i have no idea for the moment

    printf("\n~~~ SIZE Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void mtime_fuzzing(){

    printf("\n~~~ MTIME Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.mtime, sizeof(header.mtime));

    char time_to_try[sizeof(header.mtime)];
    time_t now = time(NULL); // get current time 
    printf("Seconds after 1970 : %ld\n", now);

    // Test with impossible date in the past (before 1970)
    start_header(&header);
    snprintf(time_to_try, sizeof(header.mtime), "%o", -300); // 5 minutes before 1970
    change_header_field(header.mtime, time_to_try, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_file);

    // Test with date in the past (5 minutes after 1970)
    start_header(&header);
    snprintf(time_to_try, sizeof(header.mtime), "%o", 300); // 5 minutes in 1970
    change_header_field(header.mtime, time_to_try, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_file);

    // Test with date 1 year in the past
    start_header(&header);
    snprintf(time_to_try, sizeof(header.mtime), "%lo", now - 31536000); // 1 year ago
    change_header_field(header.mtime, time_to_try, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_file);

    // Test with current date
    start_header(&header);
    snprintf(time_to_try, sizeof(header.mtime), "%lo", now);
    change_header_field(header.mtime, time_to_try, sizeof(header.mtime));;
    create_empty_tar(&header);
    extract(path_file);

    // Test with date 1 month in the future
    start_header(&header);
    snprintf(time_to_try, sizeof(header.mtime), "%lo", now + 31536000); // 1 month from now
    change_header_field(header.mtime, time_to_try, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_file);

    // Test with the maximum value for an int : TODO check if int or long int or long long int
    start_header(&header);
    snprintf(time_to_try, sizeof(header.mtime), "%lo", now + __INT_MAX__); // maximum value for int
    change_header_field(header.mtime, time_to_try, sizeof(header.mtime));
    create_empty_tar(&header);
    extract(path_file);

    // TODO : impossible date du futur (pas encore d'idée de comment implem ça)
    

    printf("\n~~~ MTIME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void chksum_fuzzing(){
    printf("\n~~~ CHECKSUM Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.chksum, sizeof(header.chksum));

    // TODO : need other idea
    printf("\n~~~ CHECKSUM Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void typeflag_fuzzing(){

    printf("\n~~~ TYPEFLAG Header Fuzzing ~~~\n");

    // TODO : Single char element : BRUTE-FORCE GO BRRRRRRRRRRRRRRRRRRRRRRRRR

    printf("\n~~~ TYPEFLAG Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void linkname_fuzzing(){
    printf("\n~~~ LINKNAME Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.linkname, sizeof(header.linkname));
    // TODO : linkname not leading anywhere. Comments of Marco from the future : I have absolutely no idea what I meant there.
    printf("\n~~~ LINKNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void magic_fuzzing(){

    printf("\n~~~ MAGIC Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.magic, sizeof(header.magic));

    printf("\n~~~ MAGIC Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void version_fuzzing(){

    printf("\n~~~ VERSION Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.version, sizeof(header.version));

    // only 2 bits, so we can go BRRRRRRRRRRRR and brute-force every value 
    // TODO : it is octal only I think tho

    printf("\n~~~ VERSION Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
}

void uname_fuzzing(){

    printf("\n~~~ UNAME Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.uname, sizeof(header.uname));

    // TODO : need other idea

    printf("\n~~~ UNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");

}

void gname_fuzzing(){

    printf("\n~~~ GNAME Header Fuzzing ~~~\n");

    fuzzing_on_precise_field(header.gname, sizeof(header.gname));

    // TODO : need other idea

    printf("\n~~~ GNAME Header Fuzzing COMPLETED SUCCESSFULLY ~~~\n");
    
}

void end_of_file() {

    // Define lengths to test
    int end_lengths[] = {0, 1, END_BYTES / 2 , END_BYTES - 1, END_BYTES, END_BYTES + 1, END_BYTES * 2};
    // Define longest buffer of 0 possible
    char end_bytes[END_BYTES * 2];
    memset(end_bytes, 0, END_BYTES * 2);
    char content[] = "https://www.youtube.com/watch?v=xvFZjo5PgG0"; // dummy text
    size_t content_size = strlen(content);

    for (int i = 0; i < (int) sizeof(end_lengths); i++){

        start_header(&header);
        // Without file content
        create_tar(&header, "", 0, end_bytes, end_lengths[i]);
        extract(path_file);


        // With file content 
        // Define field_size of content
        change_size(&header, content_size);
        //snprintf(header.field_size, 12, "%011o", content_field_size); // octal value for the checksum : crash without it, no fucking idea why (TODO : make it a function since it is the second time i used it)
        create_tar(&header, content, content_size, end_bytes, end_lengths[i]);
        extract(path_file);
    }
}


void remove_files() {

    // dunno yet which files to remove

    //system("rm -f archive.tar");
    //system("rm -r *.txt");
}


void fuzz(){
    printf("path_file : %s\n", path_file); // can a variable become const during the running phase ?????

    // // absolument dégeulasse mais je sais plus comment const une variable du running phase
    name_fuzzing();
    // mode_fuzzing();
    // uid_fuzzing();
    // gid_fuzzing();
    // field_size_fuzzing();
    // mtime_fuzzing();
    // chksum_fuzzing();
    // typeflag_fuzzing();
    // linkname_fuzzing();
    // magic_fuzzing();
    // version_fuzzing();
    // uname_fuzzing();
    // gname_fuzzing();


    // end_of_file();

    // all the functions to test each headers
    // in each function, test extraction at the end 


    printf("Number of tries     : %d\n", number_of_try);
    printf("Number of successes : %d\n", number_of_success);

    remove_files();
}



int main(int argc, char* argv[]){

    if (argc != 2) {
        printf("Invalid number of arguments.\n");
        printf("This is a valid command : ./fuzzer <path to the tar extractor>");
        return -1;
    }
    path_file = argv[1];
    fuzz(); 
}
