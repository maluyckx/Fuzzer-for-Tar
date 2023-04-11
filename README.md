# Fuzzer for tar

## Deleted files

To ensure that your files are not unintentionally deleted when testing our project with new files, please carefully review the comments provided in the `remove_files` function of the `main.c` file.

## Description of the program

The goal of this program is to write a generation-based fuzzer for the tar extractor, which will automatically generate input files and check whether the extractor crashes. Input files that successfully crash the extractor are kept by the fuzzer.

The program has two main parts :

1) **Fuzzing on header fields** : We fuzz on each part of the header by trying different approaches such as not using ASCII characters, leaving that part empty, etc. This function is called `fuzzing_on_precise_field` and is the general fuzzing part of the project.

2) **Specialized fuzzing functions** : There are also specialized functions to fuzz on specific parts of the header.

After running the program, there will be a small summary in this form : 
```
Test status
Number of trials : X
Number of success: X

Success with 
             Empty field                       : X
             non ASCII field                   : X
             non numeric field                 : X
             too short field                   : X
             non octal field                   : X
             field cut in middle               : X
             field null terminated             : X
             field with null byte in the middle: X
             field with no null bytes          : X
             field with special character      : X
             field with negative value         : X

Success on 
           name field       : X
           mode field       : X
           uid field        : X
           gid field        : X
           size field       : X
           mtime field      : X
           checksum field   : X
           typeflag field   : X
           linkname field   : X
           magic field      : X
           version field    : X
           uname field      : X
           gname field      : X
           end of file field: X
```
The functions in the file `help.c` that were provided were split into different files for more convenience.

## How to use the program

1) Use `make` to compile the program.
2) Run the program with `./fuzzer <path to the tar extractor>`. For example: `./fuzzer ./src/extractor`

## Useful links used
- https://www.gnu.org/software/tar/manual/html_node/Standard.html
- https://theasciicode.com.ar/

## Authors : Matricule (ULB)
- Luyckx Marco : 496283
- Vanmuysewinkel Vincent : 489399
