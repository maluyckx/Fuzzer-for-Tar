#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"


static tar_header header; // really bad coding practice but otherwise, I would need to pass the arg to EVERY function in this project

void fuzzing_on_precise_field(char* path, char* field_name) {

    // function to fuzz on the header part
    // empty, not ascii, buchered in the middle, to short, not the correct format, 


    size_t size = sizeof(field_name);
    printf("Size of the field: %ld", size);

    // #### Empty
    start_header(&header);
    //print_header(&header);
    change_header_field(field_name, "", size);
    create_empty_tar(&header);
    extract(path);

    // #### not ASCII
    start_header(&header);
    //print_header(&header);
    change_header_field(field_name, 'Ω', size); // omega : is represented in Unicode by the code point U+03A9
    create_empty_tar(&header);
    extract(path);

    // #### not Numeric 
    start_header(&header);
    //print_header(&header);
    change_header_field(field_name, 'https://www.youtube.com/watch?v=oLsVrshvOaI', size); // warning is FINE : it is NORMAL that it is too long
    create_empty_tar(&header);
    extract(path);

    // #### too short (like my )


    // #### Not Octal
    start_header(&header);
    //print_header(&header);
    memset(field_name, '9', size - 1); // like we say in french : 'simple et efficace' 
    field_name[size - 1] = 0;
    create_empty_tar(&header);
    extract(path);


    // #### Cut in the middle
    start_header(&header);
    //print_header(&header);
    memset(field_name, 0, size);
    memset(field_name, '1', size / 2 );
    create_empty_tar(&header);
    extract(path);

    // #### Not terminated by the right thing 
    start_header(&header);
    //print_header(&header);
    memset(field_name, '5', size);
    create_empty_tar(&header);
    extract(path);



    // TODO
    
    // check \0 (probably several tests to do for this one)

    // modify order or placement of header parts

    // special characters, whitespace, or control characters.

    // Vincent
    // end-of-file marker
    // 2x 512 bytes filled with 0s should be present but not mandatory
    // should issue a warning if not found
}

void remove_null_terminators(char* path, char* field_name) { 
    size_t size = sizeof(field_name);

    // find first terminator:
    size_t first_term = size;
    for (size_t i=0; i<size; i++) {
        if (field_name[i] == '\0') {
            first_term = i;
            break;
        }
    }

    memset(field_name+first_term, ' ', size - first_term); // replace '\0' by ' '
    create_empty_tar(&header);
    extract(path);
}



void name_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE NAME HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    fuzzing_on_precise_field(path, header.name);

    // remove null terminators for name
}

void mode_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE MODE HEADER MA BOIIIIIIIIIIIIIII ##### \n");
    
}

void uid_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE UID HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    // fake uid
}

void gid_fuzzing(char* path){
    
    printf("\n ##### WE FUZZING THE GID HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    // fake guid
}

void size_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE SIZE HEADER MA BOIIIIIIIIIIIIIII ##### \n");

}

void mtime_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE MTIME HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    // *** TIME ***
    // full dans le passé

    // dans le future

    // impossible date
    
}

void chksum_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE CHECKSUM HEADER MA BOIIIIIIIIIIIIIII ##### \n");
    

    // bad checksum
}

void typeflag_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE TYPEFLAG HEADER MA BOIIIIIIIIIIIIIII ##### \n");
    
}

void linkname_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE LINKNAME HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    // remove null terminators for linkname
    // linkname not leading anywhere
}

void magic_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE MAGIC HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    // remove null terminators for magic
}

void version_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE VERSION HEADER MA BOIIIIIIIIIIIIIII ##### \n");
    
}

void uname_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE UNAME HEADER MA BOIIIIIIIIIIIIIII ##### \n");

}

void gname_fuzzing(char* path){

    printf("\n ##### WE FUZZING THE GNAME HEADER MA BOIIIIIIIIIIIIIII ##### \n");

    // remove null terminators for gname
    
}

void end_of_file(char* path) {

    // Define lengths to test
    int end_lengths[] = {0, 1, END_BYTES / 2 , END_BYTES - 1, END_BYTES, END_BYTES + 1, END_BYTES * 2};
    // Define longest buffer of 0 possible
    char end_bytes[END_BYTES * 2];
    memset(end_bytes, 0, END_BYTES * 2);
    char content[] = "https://www.youtube.com/watch?v=xvFZjo5PgG0"; // dummy text
    size_t content_size = strlen(content);

    for (int i = 0; i < sizeof(end_lengths); i++){

        start_header(&header);
        // Without file content
        create_tar(&header, "", 0, end_bytes, end_lengths[i]);
        extract(path);


        // With file content 
        // Define size of content
        snprintf(header.size, 12, "%011o", content_size); // octal value for the checksum : crash without it, no fucking idea why (TODO : make it a function since it is the second time i used it)
        create_tar(&header, content, content_size, end_bytes, end_lengths[i]);
        extract(path);
    }
}


void remove_files() {

    // dunno yet which files to remove

}


void fuzz(char* path){
    printf("Path : %s\n", path); // can a variable become const during the running phase ?????


    // absolument dégeulasse mais je sais plus comment const une variable du running phase
    name_fuzzing(path);
    mode_fuzzing(path);
    uid_fuzzing(path);
    gid_fuzzing(path);
    size_fuzzing(path);
    mtime_fuzzing(path);
    chksum_fuzzing(path);
    typeflag_fuzzing(path);
    linkname_fuzzing(path);
    magic_fuzzing(path);
    version_fuzzing(path);
    uname_fuzzing(path);
    gname_fuzzing(path);


    end_of_file(path);

    // all the functions to test each headers
    // in each function, test extraction at the end 


    printf("Number of tries     : %d\n", number_of_try);
    printf("Number of successes : %d\n", number_of_success);

    //printf("Ratio : %d\n", );
    

    remove_files();
}



int main(int argc, char* argv[]){

    if (argc != 2) { // le prof avait mis argc < 2 mais imo c'est mieux !=
        printf("Invalid number of arguments.\n");
        return -1;
    }

    fuzz(argv[1]); // supposed path
}
