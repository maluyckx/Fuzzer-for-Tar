# Fuzzer for tar

## Description of the program

The goal of this program is to write a generation-based fuzzer for the tar extractor, which will automatically generate input files and check whether the extractor crashes. Input files that successfully crash the extractor are kept by the fuzzer.

The program has two main parts : // TODO IMPROVE THIS SENTENCES

1) **Fuzzing on header fields** : We fuzz on each part of the header by trying different approaches such as not using ASCII characters, leaving that part empty, etc. This function is called `fuzzing_on_precise_field` and is the general fuzzing part of the project.

1) **Specialized fuzzing functions** : There are also specialized functions to fuzz on specific parts of the header.

After running the program, there will be a small summary in this form : 
```
Number of tries     : X
Number of successes : Y
```
The functions in the file `help.c` that were provided were split into different files for more convenience.

## How to use the program

1) Use `makeè to compile the program.
2) Run the program with `./fuzzer <path to the tar extractor>`. For example: `./fuzzer ./extractor`

## Useful links used
- https://www.gnu.org/software/tar/manual/html_node/Standard.html

## Authors : Matricule (ULB)
- Luyckx Marco : 496283
- Vanmuysewinkel Vincent : 489399

## stupido stupido // TODO remove this part
- probably split every header part into a different file (AKA clean code my G)
- maybe split files more accordingly
- trouver un soft pour faire des comments automatiques en C
