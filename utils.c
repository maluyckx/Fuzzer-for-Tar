#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"





/**
 * Computes the checksum for a tar header and encode it on the header
 * @param entry: The tar header
 * @return the value of the checksum
 */
unsigned int calculate_checksum(struct tar_header* entry){
    // use spaces for the checksum bytes while calculating the checksum
    memset(entry->chksum, ' ', 8);

    // sum of entire metadata
    unsigned int check = 0;
    unsigned char* raw = (unsigned char*) entry;
    for(int i = 0; i < 512; i++){
        check += raw[i];
    }

    snprintf(entry->chksum, sizeof(entry->chksum), "%06o0", check);

    entry->chksum[6] = '\0';
    entry->chksum[7] = ' ';
    return check;
}



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

    number_of_try++;
    
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
        // TODO MARCO : need to  keep the archive somewhere
        number_of_success++;
        
        goto finally;
    }
    finally:
    if(pclose(fp) == -1) {
        printf("Command not found\n");
        rv = -1;
    }
    return rv;
}



void start_header(struct tar_header* header) {

    // Reset data of header
    memset(header, 0, sizeof(tar_header));

    char archive_number[64]; // bold assumption
    snprintf(archive_number, 64, "archive_%d.txt", number_of_tar_created++);
    number_of_tar_created++;

    sprintf(header->name, "%s", archive_number); // TODO MARCO : hacky fix, needs to find better
    sprintf(header->mode, "0007777"); // all permissions
    sprintf(header->uid, "0000000");
    sprintf(header->gid, "0000000");
    snprintf(header->size, 12, "%011o", 0); // error non octal value checksum : i guess the size needs to be in octal
    sprintf(header->mtime, "1680171080"); // today's unix date
    //checksum at the end
    header->typeflag = REGTYPE;
    header->linkname[0] = 0;
    sprintf(header->magic, TMAGIC);
    sprintf(header->version, TVERSION);

    sprintf(header->uname, "root");
    sprintf(header->gname, "root");
    sprintf(header->devmajor, "0000000");
    sprintf(header->devminor, "0000000");
    // might require padding at some point, not so sure tbh

    calculate_checksum(header);
}


void change_size(tar_header* header, size_t size) {
    snprintf(header->size, 12, "%011o", size); // Octal representation of the number with 0 as prefix : https://linux.die.net/man/3/snprintf
}


void change_header_field(char* header_field, char* new_value, size_t size) { // might not be needed but it is wayyyyy prettier
    strncpy(header_field, new_value, size);
}


void create_tar(tar_header* header, char* content, size_t content_size, char* end_bytes_buffer, size_t end_size) { // maybe need checksum at some point

    FILE *fp;
    
    fp = fopen("archive.tar", "wb");
    fwrite(header, sizeof(tar_header), 1, fp);
    fwrite(content, content_size, 1, fp);
    fwrite(end_bytes_buffer, end_size, 1, fp);
    fclose(fp);
}


void create_empty_tar(tar_header* header) { // also maybe need checksum at some point

    char end_bytes[END_BYTES];
    memset(end_bytes, 0, END_BYTES);

    create_tar(header, "", 0, end_bytes, END_BYTES);
}




// DEBUG 

void print_header(tar_header* header) { // (oui j'ai passé 2 mins de ma vie à faire cet affichage débile)
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
}




