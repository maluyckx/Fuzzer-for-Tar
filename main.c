#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"






/**
 * Launches another executable given as argument,
 * parses its output and check whether or not it matches "*** The program has crashed ***".
 * @param the path to the executable
 * @return -1 if the executable cannot be launched,
 *          0 if it is launched but does not print "*** The program has crashed ***",
 *          1 if it is launched and prints "*** The program has crashed ***".
 *
 * BONUS (for fun, no additional marks) without modifying this code,
 * compile it and use the executable to restart our computer.
 */
int extract(char* path){ // PROF FUNCTION
    // Comments de Marco : la partie ici en dessous, on va 100% devoir la mettre dans une fonction vue qu'on va l'apl à chaque fin de test
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
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}





void fuzz(char* path){
    printf("Path : %s", path);

    // all the functions to test each headers
    // in each function, test extraction at the end 


    printf("Number of tries     : %d\n", number_of_try);
    printf("Number of successes : %d\n", number_of_success);

    //printf("Ratio : %d\n", );
    
}



int main(int argc, char* argv[]){

    if (argc != 2) { // le prof avait mis argc < 2 mais imo c'est mieux !=
        printf("Invalid number of arguments.\n");
        return -1;
    }

    fuzz(argv[1]); // supposed path
}