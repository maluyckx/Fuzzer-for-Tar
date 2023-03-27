# Fuzzer for tar

## Description of the program

We need to write a generation-based fuzzer for the tar extractor. The fuzzer should automatically generate input files and check whether the extractor crashes. Input files that succesfully crash the extractor are kept by the fuzzer.

After running the program, there will be a small summary in this form : 
```
Number of tries     : X
Number of successes : Y
```
The functions in the file 'help.c' that was provided were split in different files for more convenience.

## How to use the program

just use `make` lol

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
