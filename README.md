*Image goes here*
___
# Font_Blanc_C
## Overview
Font_Blanc_C is an unconventional encryption algorithm which uses matrix multiplication to permute, or reorder, data stored in a byte-array.  

For encryption, the program takes a file and encryption key as input and outputs a second file which contains the reordered bytes of the input file. The output file contains all the bytes of the input file, but in meaningless order. Internally, the algorithm performs linear transformations on the file data with permutation matrices generated from the encryption key.  
The only way to decrypt a file is to perform the reverse linear transformations generated by the key used for encryption. Using a different key for decryption will generate different permutation matrices and will therefore arbitrarily reorder the data again instead of returning it to its meaningful order.  

The program has built-in multipass encryption, supporting up to 10 layers of encryption. Each layer may use a different key and either encrypts the file in fixed-sized chunks (faster) or variable-sized chunks (more secure).  

## Documentation Table of Contents  
> [Terminology](#terminology)  
> [Theory](#theory)   
>> [Using Linear Transformations to Encrypt Data](#using-linear-transformations-to-encrypt-data)  
>> [Encryption in Chunks](#encryption-in-chunks)  
>
> [Performance](#performance)  
>> [Independent Variables and Testing Methodology](#independent-variables-and-testing-methodology)  
>> [Single Threaded Benchmark](#single-threaded-benchmark)  
>> [Multithreading the Generation of Permutation Matrices](#multithreading-the-generation-of-permutation-matrices)  
>> [Multithreading Linear Transformations](#multithreading-linear-transformations)  
>> [Combined Multithreading](#combined-multithreading)  
>
> [Usage](#usage)  
>> [Execution Flags](#execution-flags)  
>> [Instruction Flags](#instruction-flags)  
>> [Example: Simple](#example-simple)  
>> [Example: Intermediate](#example-intermediate)  
>> [Example: Multipass Encryption](#example-multipass-encryption)  
>
> [Endnotes](#endnotes)  
> 
[Return to table of contents](#documentation-table-of-contents)  

## Terminology
The following terms show up in this documentation and are defined here in context of the program.  
| Term | Definition |  
| ---: | :--------- |
| Linear tranformation | A function which takes a vector as input and outputs a vector mapped to a different (linear) vector space[<sup>1</sup>](#endnotes). In this case, the function is multiplication by a matrix. |
| Orthogonal matrix | A square matrix whose inverse is equal to its transpose. |  
| Permutation matrix | An orthogonal matrix which, when multiplied with a vector, interchanges the rows of the vector with each other[<sup>2</sup>](#endnotes). The content of the vector is preserved, but the order of the contents is not. |  
| Dot product | A mathematical operation which takes two equal-length vectors and returns a single number. Denoted `a⋅b`, for some vectors `a` and `b`. |
| Matrix inverse | The inverse of matrix M, denoted M⁻¹, is the matrix such that multiplying M with M⁻¹ equals the identity matrix, I. M⁻¹M = I. |  
| Data integrity check | All linear transformations by an orthogonal matrix preserve dot product. For a data vector `d`, an arbitrary "check" vector `c`, and an orthogonal permutation matrix `M`, `d⋅c = Md⋅Mc`[<sup>3</sup>](#endnotes). Therefore, the integrity of some encrypted data can be checked by comparing the dot products of the data with an arbitrary "check" vector before and after they have been transformed. | 
| Instruction | A user defined rule which completely describes a single pass of encryption. It necessarily includes the encryption key and the permutation matrix dimension and can include further options such as data integrity checks. |  
| Multipass encryption | The process of encrypting a file multiple times in sequence. Also called multilevel encryption. |  

## Theory  
### Using Linear Transformations to Encrypt Data
The Font_Blanc_C algorithm is predicated on the fact that the multiplication of a vector with an invertible matrix can be perfectly reversed by multiplying the resultant vector with the inverse of said invertible matrix.  

    Theorem A:
    For some invertible matrix M, and some vectors a and b, it is true that
    Ma = b and M⁻¹b = a  

Consider the byte array containing a file's data to be a vector of length n, where n is the number of bytes in the file. If we create an inveritble n-dimensional square matrix, M, and multiply it with the file vector, the resultant vector will be a transformed (encrypted) version of the data. By Theorem A, to reverse the transformation (decrypt the data) we have to calculate the inverse of M and then multiply it with the encrypted data vector. However, despite the fact that this is a functional encryption process, in practice it is too computationally expensive to 1) generate an arbitrary invertible matrix from an encryption key and 2) calculate its inverse.  

Is there a way to harness the simple encrypt and decryptability of a vector via linear transformation outlined in Theorem A without the use of expensive algorithms?  

Enter, permutation matrices! Permutation matrices are orthogonal by definition, meaning their transpose is also their inverse. Calculating the transpose of a square matrix has a time complexity of O(n), a vast improvement over calculating inverse which cannot be done in less than O(n<sup>2</sup>) time[<sup>4</sup>](#endnotes). Therefore, an algorithm that can efficiently generate unique permutation matrices from encryption keys would solve both problems.  

### Encryption in Chunks
Creating a permutation matrix the size of the length of an input file would be ideal because it would result in a true reordering of bytes. However it is far too computationally expensive to generate a matrix that large and perform matrix multiplication with it. To combat this, the Font_Blanc_C algorithm splits an input file into discrete chunks and then uses permutation matrices to reorder the bytes in each chunk. The file can either be split into chunks of the same dimension, or chunks of pseudo-random variable dimension determined by the encryption key. Encrypting a file using fixed-dimension chunks is faster because no more than 2 permutation matrices ever need to be generated to encrypt the entire file irrespective of its length. Encrypting a file using variable-dimension chunks is more secure because the dimension of each chunk is derived from the encryption key. This means that a brute force attack attempting to reorder the bytes in each chunk would be significantly harder since the start and end of each chunk is unknown without the encryption key.

Encrypting in chunks is less than ideal because it means that reordered bytes stay relatively close to their original position, but it's a necessary compromise for efficiency. The issue can be mitigated to some extent by performing multiple passes of encryption using a mix of differing fixed-dimension passes and variable-dimension passes.  

## Performance  
### Independent Variables and Testing Methodology
To measure performance, I've defined 2 major sections of the program whose elapsed execution times will be anlalyzed:  
1) the generation of permutation matrices
2) the execution of linear transformations (matrix multiplication)   

I've chosen these two sections because combined they make up over 50% of the runtime of the program and they're both parallelizable.

For all tests I used [this]() PDF of the U.S. Constitution named `Constitution.pdf`. The test file, as it will be referred to, is 4488706 bytes (4.3 MiB) long. All tests were run on a 2-core, 4-thread, Intel(R) Core(TM) i7-7500U CPU @ 2.7GHz. All testing was done in file encryption because decryption is expected to have the same performance. The data presented here for each experimental group is the average result of 5 runs.  

Program speedup calculations were performed using Amdahl's Law defined as follows:

    S(N) = Maximum speedup
    N = Number of processors (factor of parallelizability)
    P = Proportion of runtime that is parallelizable
    
    S(N) = 1 / ((1 - P) + (P / N))  
    
### Single Threaded Benchmark
In order to determine which sections of the program take up the most runtime, I ran control tests for both fixed-dimension and variable-dimension encryption.
The following table is the result of the fixed-dimension test. Specifically, a single pass of single-threaded encryption on the test file using a permutation matrix dimension of 4096. The command ran:
    
    $ ./fontblanc Constitution.pdf -e -D 4096 -k fookeybar  

| Measured Section | Time (ms) | Proportion of Runtime (%) |  
| :-------------- | :-------: | :----------: |  
| Generating matrices | 49.81 | 35 |  
| Linear transformations | 55.46 | 39 |  
| Rest of program | 36.18 | 26 |  
| Elapsed time | 141.45 | 100 |  

The following table is the results of the variable-dimension test. Specifically, a single pass of single-threaded, variable-dimension encryption on the test file. The command ran:

    $ ./fontblanc Constitution.pdf -e -k fookeybar  

| Measured Section | Time (ms) | Proportion of Runtime (%) |  
| :-------------- | :-------: | :----------: |  
| Generating matrices | 707.27 | 87 |  
| Linear transformations | 60.63 | 7.5 |  
| Rest of program | 45.02 | 5.5 |  
| Elapsed time | 812.92 | 100 |  

The data shows that the generation of permutation matrices and the linear transformations both take up a similar proportion of the runtime for fixed-dimension encryption while the generation of permutation matrices takes up a significanly larger proportion of runtime for variable-dimension encryption. This is expected because no more than 2 matrices need to be generated for fixed-dimension while up to 10 matrices need to be generated for variable-dimension. It is worth noting that the time for linear transformations is almost the same in both tests. This is due to the fact that the input file is the same, so a similar number of transformations are applied in both tests.  

In conclusion, the time to generate permutation matrices is the largest contributing factor to varying execution times and, therefore, is the area that optimization efforts should be focused.  

### Multithreading the Generation of Permutation Matrices
To increase the performance of generating permutation matrices, I designed 2 multithreading schemes which will be referred to as permut-pthread and permut-pthread-join. Both schemes schedule the generation of each matrix to a new thread, but permut-pthread-join synchronizes the completion of the threads while permut-pthread does not.  

For fixed-dimension encryption, since matrix generation makes up 35% of the runtime, by [Amdahl's Law](#independent-variables-and-testing-methodology) I'm expecting an approximate speedup of 1.2. The speedup is limited by the fact that only 2 matrices need to be generated, therefore the factor of parallelizability cannot be greater than 2 because each thread only handles 1 matrix.  

The graph below shows how both schemes perform compared to a single-threaded control run with the same input. Displayed is elapsed time vs the number of threads for 3 passes of fixed-dimension encryption.

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Graphics/GenPmat_Fixed.png" Alt="Elapsed Time vs Number Threads for Fixed-Dimension Encryption" width="600"></img>  

Evidently, the permut-pthread scheme is marginally better than permut-pthread-join. As expected, the performance gain appears at 2 threads and doesn't improve when using more. The average permut-pthread execution time with 2 or more threads was approximately 416 ms. The control execution time was 539 ms. This is a speedup of 1.3.  

For variable-dimension encryption, since matrix generation makes up 87% of the runtime, by [Amdahl's Law](#independent-variables-and-testing-methodology) I'm expecting an approximate speedup of 2.8. Since there are 10 matrices to generate for variable-dimension encryption, the maximum speedup would be achieved by running 10 threads in parallel however my CPU limits the factor of parallelizability to 4 since it's dual core hyperthreaded at 2 threads per core.

The graph below shows how both schemes perform compared to a single-threaded control run with the same input. Displayed is the elapsed time vs number of threads for 3 passes of variable-dimension encryption.  

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Graphics/GenPmat_Variable.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="600"></img>  

Again the permut-pthread scheme performs better than permut-pthread-join. As expected, the maximum performance gain is achieved at 4 threads and doesn't improve when using more. The average permut-pthread execution time with 4 or more threads was approximately 1086 ms. The control execution time was 2400 ms. This is a speedup of 2.21—around 75% of the ideal speedup.  

In conclusion, the permut-pthread scheme is the best multithreading scheme for optimizing the generation permutation matrices.

### Multithreading Linear Transformations
Although performing linear transformations only makes up a small proportion of the program runtime, the process is easily parallelizable. Since the input file is split into discrete chunks, each chunk can be operated on independently and in any order. If matrix multiplications and data accesses are performed in parallel there will not be a race condition because the permutation matrices used in the transformations are read-only and all chunks write different segments of file data.  

I designed 2 multithreading schemes which will be referred to as pthread and pthread-chunk. Pthread creates a new thread for every single linear transformation (one thread per  chunk). Pthread-chunk splits the file into a number of segments equal to the max number of threads and then each thread to processes all chunks within its segment. I expect pthread-chunk to perfrom better because it schedules far fewer threads and should have less overhead from thread-switching.  

For fixed-dimension, since linear transformations make up 39% of the runtime, by [Amdahl's Law](#independent-variables-and-testing-methodology) I'm expecting an approximate speedup of 1.4. As previously, the CPU limits the factor of parallelizability to 4.  

The graph below shows how the two schemes perform compared to a single-threaded control run with the same input. Displayed is the elapsed time vs number of threads for 3 passes of fixed-dimension encryption.  

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Graphics/LinTrans_Fixed.png" Alt="Elapsed Time vs Number Threads for Fixed-Dimension Encryption" width="600"></img>  

As predicted, pthread-chunk performs better than pthread. Notably, pthread performs worse than the control when ran single-threaded which is indicative of the amount of unecessary overhead it introduces. The average pthread-chunk execution time with 4 or more threads was approximately 395 ms. The control execution time was 539 ms. This is a speedup of 1.36.  

For variable-dimension, since linear transformations make up 7.5% of the runtime, by [Amdahl's Law](#independent-variables-and-testing-methodology) I'm expecting an approximate speedup of 1.05. As previously, the CPU limits the factor of parallelizability to 4.  

The graph below shows how the two schemes perform compared to a single-threaded control run with the same input. Displayed is the elapsed time vs number of threads for 3 passes of variable-dimension encryption.  

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Graphics/LinTrans_Variable.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="600"></img>  

Similar to the previous test, the graph illustrates that pthread-chunk performs better pthread, although by a smaller margin. Pthread again performs worse than control when ran single-threaded. The average pthread-chunk execution time with 4 or more threads was approximately 2288 ms. The control execution time was 2401 ms. This is a speedup of 1.05.

In conclusion, the pthread-chunk scheme is the best multithreading scheme for optimizing the performing of linear transformations.  

### Combined Multithreading
After determining that permut-pthread and pthread-chunk were the best schemes for multithreading the generation of permutation matrices and performing linear transformations, repsectively, I combined them into a single scheme which will be referred to as permut-pthread-chunk.

For fixed-dimension, taking into account that maxtrix generation (35% runtime) is limited to a factor of parallelizability of 2 and linear transformations (39% of runtime) is limited to a factor of parallelizability of 4, by [Amdahl's Law](#independent-variables-and-testing-methodology) I'm expecting an approximate speedup of 1.9.  

The graph below shows how the two schemes perform independently and combined compared to a single-threaded control run with the same input. Displayed is the elapsed time vs number of threads for 3 passes of fixed-dimension encryption.  

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Graphics/Combined_Fixed.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="600"></img>  

The average permut-pthread-chunk execution time with 4 or more threads was 269 ms. The control execution time was 539 ms. This is a speedup of 2.  

For variable-dimension, taking into account that matrix generation and linear transformations make up 94.5% of the runtime and are both limited to a factor of parallelization of 4, by [Amdahl's Law](#independent-variables-and-testing-methodology) I'm expecting an approximate speedup of 3.4.  

The graph below shows how the two schemes perform independently and combined compared to a single-threaded control run with the same input. Displayed is the elapsed time vs number of threads for 3 passes of variable-dimension encryption.  

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Graphics/Combined_Variable.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="600"></img>  

The average permut-pthread-chunk execution time with 4 or more threads was 954 ms. The control execution time was 2401 ms. This is a measured speedup of 2.5—around 75% of the ideal speedup, similar to the variable-encryption tests for the generation of permutation matrices.  

The current version of Font_Blanc_C uses the permut-pthread-chunk multithreading scheme. From these tests it can be inferred that for any given number of threads, the speedup of the program will be approximately 75% of the ideal speedup calculated with Amdahl's Law.

## Usage
Run with `fontblanc <input filepath> <options ...>`.  

### Execution Flags
The initial command to run the program will contain the file to operate on, global flags, and, optionally, the first instruction. If the first instruction isn't contained in the initial command's arguments, then the program will automatically start in interactive instruction input mode.  
| Flag | Description |
|:----:| :---------- |
| h    | Print general help. |
| e    | Run in encrypt mode. |
| d    | Run in decrypt mode. |
| t    | Set max number of threads to use. Expects argument. If not invoked, defaults to single-threaded. For efficient performance, set to the number of cores on the machine's CPU. For maximum performance on hyperthreaded CPU's, set to number of cores multiplied by number of threads per core. |
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
<sup>4</sup>“Computational Complexity of Mathematical Operations.” Wikipedia, Wikimedia Foundation, 5 July 2021, https://en.wikipedia.org/wiki/Computational_complexity_of_mathematical_operations#Matrix_algebra. 
