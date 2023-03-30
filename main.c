#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"







// *** Header test ***
void trying_to_fuck_up_the_header(char* path, tar_header header) {

    start_header(&header);
    print_header(&header);


    
    extract(path);


    // test empty

    // test not ASCII

    // test cut in the middle

    // test to short 

    // test not correct format
    // remove null terminators for name, linkname, magic, uname and gname

    // fake uid/guid

    // bad checksum

    // linkname not leading anywhere



}







// *** TIME ***

// full dans le passé

// dans le future

// impossible date


// end-of-file marker
// 2x 512 bytes filled with 0s should be present but not mandatory
// should issue a warning if not found




void remove_files() {

    // dunno yet which files to remove

}


void fuzz(char* path){
    printf("Path : %s\n", path);

    tar_header header;

    trying_to_fuck_up_the_header(path, header);

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
