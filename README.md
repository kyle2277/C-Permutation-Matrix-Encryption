*Image goes here*
___
# Font_Blanc_C
## Documentation Table of Contents
> [Overview](#overview)  
> [Terminology](#terminology)  
> [Theory](#theory)  
>> [Mathematical Explanation](#mathematical-explanation)  
>> [Visual Explanation](#visual-explanation)  
>
> [Performance](#performance)  
> [Usage](#usage)  
>> [Execution Flags](#execution-flags)  
>> [Instruction Flags](#instruction-flags)  
>> [Example: Simple](#example-simple)  
>> [Example: Intermediate](#example-intermediate)  
>> [Example: Multipass Encryption](#example-multipass-encryption)  
>
> [Endnotes](#endnotes)  

## Overview
Font_Blanc_C is an unconventional encryption algorithm which uses matrix multiplication to permute, or reorder, data stored in a byte-array.  
[Return to table of contents](#documentation-table-of-contents)  

## Terminology
The following terms show up in this documentation and are defined here in context of the program.  
| Term | Definition |  
| ---: | :--------- |
| Linear tranformation | A function which takes a vector as input and outputs a vector mapped to a different (linear) vector space[<sup>1</sup>](#endnotes). In this case, the function is multiplication by a matrix. |
| Orthogonal matrix | A square matrix whose inverse is equal to its transpose. |  
| Permutation matrix | An orthogonal matrix which, when multiplied with a vector, interchanges the rows of the vector with each other[<sup>2</sup>](#endnotes). The content of the vector is preserved, but the order of the contents is not. |  
| Dot product | A mathematical operation which takes two equal-length vectors and returns a single number. Denoted `a⋅b`, for some vectors `a` and `b`. |
| Data integrity check | All linear transformations by an orthogonal matrix preserve dot product. For a data vector `d`, an arbitrary "check" vector `c`, and an orthogonal permutation matrix `M`, `d⋅c = Md⋅Mc`[<sup>3</sup>](#endnotes). Therefore, the integrity of some encrypted data can be checked by comparing the dot products of the data with an arbitrary "check" vector before and after they have been transformed. | 
| Instruction | A user defined rule which completely describes a single pass of encryption. It necessarily includes the encryption key and the permutation matrix dimension and can include further options such as data integrity checks. |  
| Multipass encryption | The process of encrypting a file multiple times in sequence. Also called multilevel encryption. |  

## Theory  
### Mathematical Explanation
The Font_Blanc_C algorithm is predicated on the fact that the multiplication of a vector with an invertible matrix can be perfectly reversed by multiplying the resultant vector with the inverse of said invertible matrix.  

<code>Theorem A:</code>  
<code>For some invertible matrix M, and some vectors a and b, it is true that</code>  
<code>Ma = b and M<sup>-1</sup>b = a</code>  

Imagine that all the bytes making up a file is a vector of length n. If we create an inveritble nxn matrix, M, and multiply it with the file vector, the resultant vector will be a transformed (encrypted) version of the data. By Theorem A, to reverse the transformation (decrypt the data) we have to calculate the inverse of M and then multiply it with the encrypted data vector. However, despite the fact that this process functions as an encryption algorithm in theory, in practice it is very computationally expensive to 1) generate an arbitrary invertible matrix from an encryption key and 2) calculate the inverse of an invertible matrix.  

Is there a way to harness the simple encrypt and decryptability of a vector outlined in Theorem A without the use of  expensive algorithms?  

Orthogonal matrices to the rescue! An orthogonal matrix is one whose transpose is also its inverse. Calculating the transpose of a square matrix has a time complexity of O(n), a vast improvement over matrix inverse which cannot be done in less than O(n<sup>2</sup>) time. Furthermore, all permutation matrices are orthogonal, meaning an algorithm that can efficiently generate unique permutation matrices from encryption keys would solve both problems.  


The bytes that make up a file are stored in sequence on disk which is essentially a vector. Therefore, very little processing has to be done to a file's bytes before 

### Visual Explanation

## Performance  

## Usage
Run with `fontblanc <input filepath> <options ...>`.  

### Execution Flags
The initial command to run the program will contain the file to operate on, global flags, and, optionally, the first instruction. If the first instruction isn't contained in the initial command's arguments, then the program will automatically start in interactive instruction input mode.
| Flag | Description |
|:----:| :---------- |
| h    | Print general help. |
| e    | Run in encrypt mode. |
| d    | Run in decrypt mode. |
| t    | Set max number of threads to use. Expects argument. If not invoked, defaults to single-threaded. Recommended to set to the number of cores on the machine's CPU. |
| o    | Set output filename (uses input filepath). Expects argument. If not invoked, defaults to input filename. Adds prefix (decryption) or extension (encryption) to output filename to prevent overwriting the intput file. |
| m    | Run in interactive instruction input mode (multilevel encryption/decryption). |
| v    | Verbose output. Prints information for debugging. |
| k    | Set encrypt key for first instruction. Expects argument. |
| D    | Set permutation matrix dimension for first instruction. Expects argument. Argument of 0 denotes variable-dimension encryption. If not invoked, defaults to variable-dimension encryption. |
| s    | Skip data integrity checks for fist instruction. Not recommended. |

### Instruction Flags
Instruction flags are options used to define a single encryption/decryption rule in the interactive instruction input loop.
| Flag | Description |
|:----:| :---------- |
| h    | Print instruction help. |
| k    | Set encrypt key for current instruction. Expects argument. |
| D    | Set permutation matrix dimension for current instruction. Expects argument. Argument of 0 denotes variable-dimension encryption. If not invoked, defaults to variable-dimension encryption. |
| s    | Skip data integrity checks for current instruction. Not recommended. |
| r    | Delete last instruction. |

A generic instructions is written in the form of:  
`-k <some key> -D <some dimension>`  
Omitting the `k` flag prompts the user to type the encryption key into the terminal with keyboard echoing disabled.  

### Example: Simple
The following command runs a single pass of encryption over the file `Constitution.pdf` using the key`fookeybar`. It encrypts using variable-dimension permutation matrices since the `D` flag was not invoked. It outputs a file named `Constitution.pdf.fbz`.  

    $ ./fontblanc Constitution.pdf -e -k fookeybar

    File name: Constitution.pdf
    File size: 4488706 bytes
    Mode: encrypt
    Threads: 1

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Encrypting...
    Executing instruction 1...
    Elapsed time (s): 0.816374
    Done.  

The following command decrypts the file generated by the previous encryption command. It outputs a file named `d_Constitution.pdf`.  

    $ ./fontblanc Constitution.pdf.fbz -d -k fookeybar

    File name: Constitution.pdf.fbz
    File size: 4488706 bytes
    Mode: decrypt
    Threads: 1

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Decrypting...
    Elapsed time (s): 0.801153
    Done.  
### Example: Intermediate
The following command runs a single pass of encryption over the file `Constitution.pdf` using the key`fookeybar`. The output filename is set to `Constitution_encrypted` and it runs using a maximum of 4 threads. It encrypts using variable-dimension permutation matrices since the `D` flag was not invoked. It outputs a file named `Constitution_encrypted.fbz`. 

    $ ./fontblanc Constitution.pdf -e -o Constitution_encrypted -t 4 -k fookeybar
    File name: Constitution.pdf
    File size: 4488706 bytes
    Mode: encrypt
    Threads: 4

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Encrypting...
    Executing instruction 1...
    Elapsed time (s): 0.307854
    Done.  
    
The following command decrypts the file generated by the previous encryption command, but using 8 threads instead of 4. It outputs a file named `d_Constitution.pdf`.

    $ ./fontblanc Constitution_encrypted.fbz -d -o Constitution.pdf -t 8 -k fookeybar
    File name: Constitution_encrypted.fbz
    File size: 4488706 bytes
    Mode: decrypt
    Threads: 8

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Decrypting...
    Executing instruction 1...
    Elapsed time (s): 0.293071
    Done.  
    
### Example: Multipass Encryption
The following command instructs the program to enter the instruction input loop for multipass encryption via the `m` flag. It runs using a maximum of 4 threads.  
The first instruction is defined in the program execution arguments and states to perform variable-dimension encryption using the key `fookeybar`.  
The second instruction is defined in the instruction input loop and states to perform variable-dimension encryption using the key `barkeybaz`.  
The third instruction is defined in the instruction input loop and states to perform fixed-dimension encryption using a permutation matrix size of 4096 using the key `bazkeyqux`.   
It outputs a file named `Constitution.pdf.fbz`.  

    $ ./fontblanc Constitution.pdf -e -t 4 -k fookeybar -m
    File name: Constitution.pdf
    File size: 4488706 bytes
    Mode: encrypt
    Threads: 4

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Enter an instruction using options "-k" "-D" "-s":
    $ -k barkeybaz

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    | Instruction #2 |
    Key: barkeybaz
    Matrix dimension: variable
    Data integrity checks: on

    Enter an instruction:
    $ -k bazkeyqux -D 4096

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    | Instruction #2 |
    Key: barkeybaz
    Matrix dimension: variable
    Data integrity checks: on

    | Instruction #3 |
    Key: bazkeyqux
    Matrix dimension: 4096
    Data integrity checks: on

    Enter an instruction:
    $ done

    Encrypting...
    Executing instruction 1...
    Executing instruction 2...
    Executing instruction 3...
    Elapsed time (s): 0.697083
    Done.  
    
The following command decrypts the file generated by the previous encryption command. Notice that in this example the user only defines the dimension for each instruction, so the user can type their encryption keys with keyboard echoing disabled (keystrokes are shown in the transcript for purpose of readability, but text enclosed in angle brackets would be masked in a terminal). It outputs a file named `d_Constitution.pdf`.

    $ ./fontblanc Constitution.pdf.fbz -d -t 4 -D 0 -m
    File name: Constitution.pdf.fbz
    File size: 4488706 bytes
    Mode: decrypt
    Threads: 4
    $ Enter key: <fookeybar>    // Masked input

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Enter an instruction using options "-k" "-D" "-s":
    $ -D 0
    $ Enter key: <barkeybaz>    // Masked input

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    | Instruction #2 |
    Key: barkeybaz
    Matrix dimension: variable
    Data integrity checks: on

    Enter an instruction:
    $ -D 4096
    $ Enter key: <bazkeyqux>    // Masked input

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    | Instruction #2 |
    Key: barkeybaz
    Matrix dimension: variable
    Data integrity checks: on

    | Instruction #3 |
    Key: bazkeyqux
    Matrix dimension: 4096
    Data integrity checks: on

    Enter an instruction:
    $ done
    
    Decrypting...
    Executing instruction 1...
    Executing instruction 2...
    Executing instruction 3...
    Elapsed time (s): 0.670722
    Done.  
    
## Endnotes
<sup>1</sup>3Blue1Brown. Linear Transformations and Matrices | Chapter 3, Essence of Linear Algebra. YouTube, YouTube, 7 Aug. 2016, www.youtube.com/watch?v=kYB8IZa5AuE.  
<sup>2</sup>Taboga, Marco. “Permutation Matrix.” StatLect, StatLect, www.statlect.com/matrix-algebra/permutation-matrix.  
<sup>3</sup>Cherlin, Gregory. “Lecture 26 Orthogonal Matrices.” Sites.math.rutgers.edu, Rutgers University, https://sites.math.rutgers.edu/~cherlin/Courses/250/Lectures/250L26.html. 
