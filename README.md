# Fuzzer for tar

## Description of the program

We need to write a generation-based fuzzer for the tar extractor. The fuzzer should automatically generate input files and check whether the extractor crashes. Input files that succesfully crash the extractor are kept by the fuzzer.

The program is shaped as follows : 

We are fuzzing on each part of the header by trying different approaches like not using ASCII character, leaving that part empty, etc. This function is called "fuzzing_on_precise_field" and is kind of the general fuzzing part of the project.

There are also specialized functions to fuzz on specific part like (no idea for now but we will need them for sure).

After running the program, there will be a small summary in this form : 
```
Number of tries     : X
Number of successes : Y
```
The functions in the file 'help.c' that was provided were split in different files for more convenience.

## How to use the program

just use `make` lol

then `./fuzzer <path to the tar extractor>`
like `./fuzzer ./extractor`

## Useful links used
- https://www.gnu.org/software/tar/manual/html_node/Standard.html
-

## Authors : Matricule (ULB)
- Luyckx Marco : 496283
- Vanmuysewinkel Vincent : 489399

## stupido stupido
- probably split every header part into a different file (AKA clean code my G)
- maybe split files more accordingly
- makefile : pas oublier le '-o3' quand on aura fini 
- trouver un soft pour faire des comments automatiques en C
- FIX LES PUTAINS DE WARNINGS SA MERE
- need to check the checksum EACH time => do a function for that
