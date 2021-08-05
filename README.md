<p align="center">
<img src="https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/CPME_logo.png" Alt="CPME - C Permutation Matrix Encryption logo" width="450"></img>
</p>  

___
# C Permutation Matrix Encryption  
*This program was developed under the name Font_Blanc_C*
## Overview
C Permutation Matrix Encryption (CPME) is a proof of concept encryption algorithm which uses matrix multiplication to permute, or reorder, data stored in a byte-array.  

For encryption, the program takes a file and encryption key as input and outputs an encrypted file. The output file contains all the bytes of the input file, but in an arbitrary order. Internally, the algorithm performs linear transformations on the file data with permutation matrices generated from the encryption key.  
The only way to decrypt a file is to perform the reverse linear transformations generated by the key used for encryption. Using a different key for decryption will generate different permutation matrices and will therefore arbitrarily reorder the data again instead of returning it to its meaningful order.  

The program has built-in multipass encryption, supporting up to 10 layers of encryption. Each layer may use a different key and either encrypts the file in fixed-sized chunks (faster) or variable-sized chunks (more secure).  

## Documentation Table of Contents  
> [Terminology](#terminology)  
> [Theory](#theory)   
>> [Using Linear Transformations to Encrypt Data](#using-linear-transformations-to-encrypt-data)  
>> [Encryption in Chunks](#encryption-in-chunks)  
>
> [Usage](#usage)  
>> [Options](#options)  
>> [Interacitve Instruction Input Mode](#interactive-instruction-input-mode)  
>> [Example: Simple](#example-simple)  
>> [Example: Intermediate](#example-intermediate)  
>> [Example: Multipass Encryption](#example-multipass-encryption)  
>
> [Performance Optimization](#performance-optimization)  
>> [Testing Methodology](#testing-methodology)  
>> [Single Threaded Benchmark](#single-threaded-benchmark)  
>> [Multithreading the Generation of Permutation Matrices](#multithreading-the-generation-of-permutation-matrices)  
>> [Multithreading Linear Transformations](#multithreading-linear-transformations)  
>> [Combined Multithreading](#combined-multithreading)  
>> [Result of Experiments](#result-of-experiments)  
>
> [Endnotes](#endnotes)  
> 
[Return to table of contents](#documentation-table-of-contents)  

## Terminology
The following are a handful of relevant terms defined in context of the program.  
| Term | Definition |  
| :--- | :--------- |
| Linear tranformation | A function which takes a vector as input and outputs a vector mapped to a different (linear) vector space[<sup>1</sup>](#endnotes). In this case, the function is multiplication by a matrix. |
| Orthogonal matrix | A square matrix whose inverse is equal to its transpose. |  
| Permutation matrix | An orthogonal matrix which, when multiplied with a vector, interchanges the rows of the vector with each other[<sup>2</sup>](#endnotes). The content of the vector is preserved, but the order of the contents is not. |  
| Dot product | A mathematical operation which takes two equal-length vectors and returns a single number. Denoted `a⋅b`, for some vectors `a` and `b`. |
| Matrix inverse | The inverse of matrix M, denoted M⁻¹, is the matrix such that multiplying M with M⁻¹ equals the identity matrix, I. M⁻¹M = I. |  
| Data integrity check | All linear transformations by an orthogonal matrix preserve dot product. For a data vector `d`, an arbitrary "check" vector `c`, and an orthogonal permutation matrix `M`, `d⋅c = Md⋅Mc`[<sup>3</sup>](#endnotes). Therefore, the integrity of some encrypted data can be checked by comparing the dot products of the data with an arbitrary "check" vector before and after they have been transformed. | 
| Instruction | A user defined rule which completely describes a single pass of encryption. It necessarily includes the encryption key and the permutation matrix dimension and can include further options such as a data integrity check. |  
| Multipass encryption | The process of encrypting a file multiple times in sequence. Also called multilevel encryption. |  

## Theory  
### Using Linear Transformations to Encrypt Data
The CPME algorithm is predicated on the fact that the multiplication of a vector with an invertible matrix can be perfectly reversed by multiplying the resultant vector with the inverse of said invertible matrix.  

    Theorem A:
    For some invertible matrix M, and some vectors a and b, it is true that
    Ma = b and M⁻¹b = a  

Consider the byte array containing a file's data to be a vector of length n, where n is the number of bytes in the file. If we create an inveritble n-dimensional square matrix, M, and multiply it with the file vector, the resultant vector will be a transformed (encrypted) version of the data. By Theorem A, to reverse the transformation (decrypt the data) we have to calculate the inverse of M and then multiply it with the encrypted data vector. However, despite the fact that this is a functional encryption process, in practice it is too computationally expensive to 1) generate an arbitrary invertible matrix from an encryption key and 2) calculate its inverse.  

Is there a way to harness the simple encrypt and decryptability of a vector via linear transformation outlined in Theorem A without the use of expensive algorithms?  

Enter, permutation matrices! Permutation matrices are orthogonal by definition, meaning their transpose is also their inverse. Calculating the transpose of a square matrix has a time complexity of O(n), a vast improvement over calculating inverse which cannot be done in less than O(n<sup>2</sup>) time[<sup>4</sup>](#endnotes). Therefore, an algorithm that can efficiently generate unique permutation matrices from encryption keys would solve both problems.  

### Encryption in Chunks
Creating a permutation matrix the size of the length of an input file would be ideal because it would result in a true reordering of all the bytes in the file. However it is far too computationally expensive to generate a matrix that large and perform matrix multiplication with it. To rectify this, the CPME algorithm splits an input file into discrete chunks and then generates smaller permutation matrices to reorder the bytes in each chunk. The maximum chunk size in CPME is 8 KiB (8192 bytes).  

The file can either be split into chunks of the same dimension, or chunks of pseudo-random variable dimension determined by the encryption key. Encrypting a file using fixed-dimension chunks is faster because no more than 2 permutation matrices ever need to be generated to encrypt the entire file irrespective of its length. Encrypting a file using variable-dimension chunks is more secure because the dimension of each chunk is derived from the encryption key. This means that a brute force attack attempting to reorder the bytes in each chunk would be significantly harder since the start and end of each chunk is unknown without the encryption key.

Encrypting in chunks is less ideal because it means that reordered bytes stay relatively close to their original position, but it's a necessary compromise for efficiency. The issue can be mitigated to some extent by performing multiple passes of encryption using a mix of differing fixed-dimension passes and variable-dimension passes.  

## Usage
`fontblanc [FILE] -e [OPTIONS...]` for encryption.  
`fontblanc [FILE] -d [OPTIONS...]` for decryption.  

### Options
The initial command to execute the program will contain the input file, global options, and, optionally, the first instruction. If the first instruction isn't contained in the execution statement, then the program will automatically start in interactive instruction input mode.  
| Flag | Description |
|:----:| :---------- |
| h    | Print general help. |
| e    | Run in encrypt mode. |
| d    | Run in decrypt mode. |
| t    | Set max number of threads to use. Expects argument. If not invoked, defaults to single-threaded. For efficient performance, set to the number of cores on the machine's CPU. For maximum performance on hyperthreaded CPU's, set to number of cores multiplied by number of threads per core. |
| o    | Set output filename (uses input filepath). Expects argument. If not invoked, defaults to input filename. Adds prefix (decryption) or extension (encryption) to output filename to prevent overwriting the intput file. |
| m    | Run in interactive instruction input mode (multilevel encryption/decryption). |
| v    | Verbose output level I. Prints instructions as they are added. |
| V    | Verbose output level II. Prints debugging information. |
| k    | Set encrypt key for first instruction. Expects argument. |
| D    | Set permutation matrix dimension for first instruction. Expects argument. Argument of 0 denotes variable-dimension encryption. If not invoked, defaults to variable-dimension encryption. |
| s    | Skip data integrity checks for fist instruction. Not recommended. |

### Interactive Instruction Input Mode
Interactive instruction input mode is a user input loop which allows the user to define one or more encryption/decryption instructions which will be applied in sequence. To successfully decrypt a multipass encrypted file, the user must input the exact same instructions in the same order as used for encryption.  

The user can manually enter the instruction input loop by invoking the `-m` flag on the command line. The program will automatically enter the instruction input loop if no initial instruction is defined in the program execution statement.   

The following flags are used to define a single encryption/decryption rule in the interactive instruction input loop.
| Flag | Description |
|:----:| :---------- |
| h    | Print instruction help. |
| k    | Set encrypt key for current instruction. Expects argument. |
| D    | Set permutation matrix dimension for current instruction. Expects argument. Argument of 0 denotes variable-dimension encryption. If not invoked, defaults to variable-dimension encryption. |
| s    | Skip data integrity checks for current instruction. Not recommended. |
| r    | Delete the last instruction. |
| p    | Print single instruction at specified position. Expects argument. |
| P    | Print all instructions. |
| Enter | Execute instructions. |  

A generic instructions is written in the form of:  
`-k [SOME KEY] -D [SOME DIMENSION]`  
Omitting the `k` flag prompts the user to type the encryption key into the terminal with keyboard echoing disabled.  
Press `Enter` to run after all instructions have been input.  

### Example: Simple
The following command runs a single pass of encryption over the file `Constitution.pdf` using the key`fookeybar`. It encrypts using variable-dimension matrices since the `D` flag was not invoked. Verbose output level I is enabled so instruction details are printed. It outputs a file named `Constitution.pdf.fbz`.  

    ~$ ./fontblanc Constitution.pdf -e -k fookeybar -v

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

The following command decrypts the file generated by the previous encryption command. Verbose output is disabled this time so instruction details are not printed. It outputs a file named `d_Constitution.pdf`.  

    ~$ ./fontblanc Constitution.pdf.fbz -d -k fookeybar

    File name: Constitution.pdf.fbz
    File size: 4488706 bytes
    Mode: decrypt
    Threads: 1

    Instruction #1 added

    Decrypting...
    Elapsed time (s): 0.801153
    Done.  
    
### Example: Intermediate
The following command runs a single pass of encryption over the file `Constitution.pdf` using the key`fookeybar`. The output filename is set to `Constitution_encrypted` and it runs using a maximum of 4 threads. It encrypts using variable-dimension permutation matrices since the `D` flag was not invoked. Verbose output leve I is enabled. It outputs a file named `Constitution_encrypted.fbz`. 

    ~$ ./fontblanc Constitution.pdf -e -o Constitution_encrypted -t 4 -k fookeybar -v
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
    
The following command decrypts the file generated by the previous encryption command, but using 8 threads instead of 4. Verbose output level I is enabled. It outputs a file named `d_Constitution.pdf`.

    ~$ ./fontblanc Constitution_encrypted.fbz -d -o Constitution.pdf -t 8 -k fookeybar -v
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
Verbose output is disabled so instructions are not printed until the user explicitly requests it by invoking the `P` flag in the instruction input loop.  
It outputs a file named `Constitution.pdf.fbz`.  

    ~$ ./fontblanc Constitution.pdf -e -t 4 -k fookeybar -m
    File name: Constitution.pdf
    File size: 4488706 bytes
    Mode: encrypt
    Threads: 4

    Instruction #1 added

    Define instructions using the following flags:
       -k	encryption key (omit flag to enter with terminal echoing disabled)
       -D	permutation matrix dimension (defaults to variable-dimension if not invoked or set to 0)
       -s	skip data integrity checks. Not recommended
       -r	delete last instruction
       -p	print single instruction at specified position. Expects integer argument
       -P	print all instuctions
       -h	print instruction input loop help
       Enter	execute instructions
    
    Example: "-k fookeybar -D 0"

    Enter an instruction:
    ~$ -k barkeybaz
    Instruction #2 added
    Enter an instruction:
    ~$ -k bazkeyqux -D 4096
    Instruction #3 added
    Enter an instruction:
    -P                           // print all instructions
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
    ~$                           // pressed Enter

    Encrypting...
    Executing instruction 1...
    Executing instruction 2...
    Executing instruction 3...
    Elapsed time (s): 0.697083
    Done.  
    
The following command decrypts the file generated by the previous encryption command. Notice that in this example the user only defines the dimension for each instruction, so the user can type their encryption keys with keyboard echoing disabled (keystrokes are shown in the transcript for purpose of readability, but text enclosed in angle brackets would be masked in a terminal). Verbose output level I is enabled. It outputs a file named `d_Constitution.pdf`.

    ~$ ./fontblanc Constitution.pdf.fbz -d -t 4 -D 0 -m -v
    File name: Constitution.pdf.fbz
    File size: 4488706 bytes
    Mode: decrypt
    Threads: 4
    ~$ Enter key: <fookeybar>    // masked input

    | Instruction #1 |
    Key: fookeybar
    Matrix dimension: variable
    Data integrity checks: on

    Define instructions using the following flags:
       -k	encryption key (omit flag to enter with terminal echoing disabled)
       -D	permutation matrix dimension (defaults to variable-dimension if not invoked or set to 0)
       -s	skip data integrity checks. Not recommended
       -r	delete last instruction
       -p	print single instruction at specified position. Expects integer argument
       -P	print all instuctions
       -h	print instruction input loop help
       Enter	execute instructions
    
    Example: "-k fookeybar -D 0"
    
    Enter an instruction:
    ~$ -D 0
    ~$ Enter key: <barkeybaz>    // masked input

    | Instruction #2 |
    Key: barkeybaz
    Matrix dimension: variable
    Data integrity checks: on

    Enter an instruction:
    ~$ -D 4096
    ~$ Enter key: <bazkeyqux>    // masked input

    | Instruction #3 |
    Key: bazkeyqux
    Matrix dimension: 4096
    Data integrity checks: on

    Enter an instruction:
    ~$                           // presed Enter
    
    Decrypting...
    Executing instruction 1...
    Executing instruction 2...
    Executing instruction 3...
    Elapsed time (s): 0.670722
    Done.  
    
## Performance Optimization  
This section of the documentation is a detailed report of how I optimized the program via multithreading.

### Testing Methodology
#### Processes to Optimize
To measure performance, I've defined 2 major sections of the program whose elapsed execution times will be anlalyzed:  
1) the generation of permutation matrices
2) the execution of linear transformations (matrix multiplication)   

I've chosen these two sections because combined they make up over 50% of the runtime of the program and they're both parallelizable.  
#### Data Collection
All data was collected using [this](https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/run_threads.sh) Bash script. The script repeatedly runs the program with the same input using different numbers of threads. It outputs the elapsed time of each run to a file in CSV format. This data was averaged and graphed to get the results reported here.  
#### Input File
I used [this](https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/Constitution.pdf) PDF of the U.S. Constitution named `Constitution.pdf` as the input. The test file, as it will be referred to, is 4488706 bytes (4.3 MiB) long. 
#### Testing Hardware
Tests were performed on a 2-core, 4-thread (hyperthreaded), Intel(R) Core(TM) i7-7500U CPU @ 2.7GHz. 
#### Experimental Groups
For each multithreading scheme tested, I created separate experimental groups for variable-dimension and fixed-dimension runs of the program. Runs consisted of 3 layers of encryption, all either variable-dimension or fixed-dimension. The data presented for each experimental group is the average result of 5 runs. All tests were done in the file encryption mode because decryption has the same performance.  
Variable-dimension tests used [this](https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/test_variable) file as input for the instruction loop.  
Fixed-dimension tests used [this](https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/test_fixed) file as input for the instruction loop.  
#### Speedup Calculations
Program speedup upper bounds were calculated using Amdahl's Law, defined as follows:

    S(N) = Maximum speedup
    N = Number of processors (factor of parallelizability)
    P = Proportion of runtime that is parallelizable
    
    S(N) = 1 / ((1 - P) + (P / N))  
    
### Single Threaded Benchmark
In order to determine the runtime proportion of each section, I ran control tests for both fixed-dimension and variable-dimension encryption.
Table 1 is the result of the fixed-dimension test. Specifically, a single pass of single-threaded encryption on the test file using a permutation matrix dimension of 4096. The test command:
    
    ~$ ./fontblanc Constitution.pdf -e -D 4096 -k fookeybar  

| Measured Section | Time (ms) | Proportion of Runtime (%) |  
| :-------------- | :-------: | :----------: |  
| Generating matrices | 49.81 | 35 |  
| Linear transformations | 55.46 | 39 |  
| Rest of program | 36.18 | 26 |  
| Elapsed time | 141.45 | 100 |  

**Table 1:** *Proportion of runtime split between the major sections of the program for fixed-dimension encryption.*  

Table 2 is the results of the variable-dimension test. Specifically, a single pass of single-threaded, variable-dimension encryption on the test file. The test command:

    ~$ ./fontblanc Constitution.pdf -e -k fookeybar  

| Measured Section | Time (ms) | Proportion of Runtime (%) |  
| :-------------- | :-------: | :----------: |  
| Generating matrices | 707.27 | 87 |  
| Linear transformations | 60.63 | 7.5 |  
| Rest of program | 45.02 | 5.5 |  
| Elapsed time | 812.92 | 100 |  

**Table 2:** *Proportion of runtime split between the major sections of the program for variable-dimension encryption.*  

The data shows that the generation of permutation matrices and the linear transformations both take up a similar proportion of the runtime for fixed-dimension encryption while the generation of permutation matrices takes up a significanly larger proportion of runtime for variable-dimension encryption. This is expected because no more than 2 matrices need to be generated for fixed-dimension while up to 10 matrices need to be generated for variable-dimension. It is worth noting that the time for linear transformations is almost the same in both tests. This is due to the fact that the input file is the same, so a similar number of transformations are applied in both tests.  

In conclusion, the time to generate permutation matrices is the largest contributing factor to varying execution times and, therefore, is the area that optimization efforts should be focused.  

### Multithreading the Generation of Permutation Matrices
To increase the performance of generating permutation matrices, I designed 2 multithreading schemes which will be referred to as permut-pthread and permut-pthread-join. Both schemes schedule the generation of each matrix to a new thread, but permut-pthread-join synchronizes the completion of the threads while permut-pthread does not.  

For fixed-dimension encryption, since matrix generation makes up 35% of the runtime, by [Amdahl's Law](#testing-methodology) I'm expecting a maximum speedup of 1.2. The speedup is limited by the fact that only 2 matrices need to be generated, therefore the factor of parallelizability cannot be greater than 2 because each thread only handles 1 matrix.  

Plot 1 shows how both schemes perform compared to a single-threaded control run with the same input.  

<img src="https://github.com/kyle2277/Font_Blanc_C/blob/dev-permut-pthread-and-chunk/Misc/GenPmat_Fixed.png" Alt="Elapsed Time vs Number Threads for Fixed-Dimension Encryption" width="700"></img>  

**Plot 1:** *Performance comparison of permut-pthread and permut-pthread-join multithreading schemes for fixed-dimension encryption.*  

Evidently, the permut-pthread scheme is marginally better than permut-pthread-join. As expected, the performance gain appears at 2 threads and doesn't improve when using more. The average permut-pthread execution time with 2 or more threads was approximately 416 ms. The control execution time was 539 ms. This is a speedup of 1.3.  

For variable-dimension encryption, since matrix generation makes up 87% of the runtime, by [Amdahl's Law](#testing-methodology) I'm expecting a maximum speedup of 2.8. Since there are 10 matrices to generate for variable-dimension encryption, the highest speedup would be achieved by running 10 threads in parallel however my CPU limits the factor of parallelizability to 4 since it's dual core hyperthreaded at 2 threads per core.

Plot 2 shows how both schemes perform compared to a single-threaded control run with the same input.  

<img src="https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/GenPmat_Variable.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="700"></img>  

**Plot 2:** *Performance comparison of permut-pthread and permut-pthread-join for variable-dimension encryption.*  

Again the permut-pthread scheme performs better than permut-pthread-join. As expected, the maximum performance gain is achieved at 4 threads and doesn't improve when using more. The average permut-pthread execution time with 4 or more threads was approximately 1086 ms. The control execution time was 2400 ms. This is a speedup of 2.21—around 75% of the ideal speedup.  

In conclusion, the permut-pthread scheme is the best multithreading scheme for optimizing the generation permutation matrices.

### Multithreading Linear Transformations
Although performing linear transformations only makes up a small proportion of the program runtime, the process is easily parallelizable. Since the input file is split into discrete chunks, each chunk can be operated on independently and in any order. If matrix multiplications and data accesses are performed in parallel there will not be a race condition because the permutation matrices used in the transformations are read-only and all chunks write different segments of file data.  

I designed 2 multithreading schemes which will be referred to as pthread and pthread-chunk. Pthread creates a new thread for every single linear transformation (one thread per chunk). Pthread-chunk splits the file into a number of segments equal to the max number of threads and then each thread to processes all chunks within its segment. I expect pthread-chunk to perfrom better because it schedules far fewer threads and should have less overhead from thread-switching.  

For fixed-dimension, since linear transformations make up 39% of the runtime, by [Amdahl's Law](#testing-methodology) I'm expecting a maximum speedup of 1.4. As previously, the CPU limits the factor of parallelizability to 4.  

Plot 3 shows how the two schemes perform compared to a single-threaded control run with the same input.  

<img src="https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/LinTrans_Fixed.png" Alt="Elapsed Time vs Number Threads for Fixed-Dimension Encryption" width="700"></img>  

**Plot 3:** *Performance comparison of pthread and pthread-chunk for fixed-dimension encryption.*  

As predicted, pthread-chunk performs better than pthread. Notably, pthread performs worse than the control when ran single-threaded which is indicative of the amount of unecessary overhead it introduces. The average pthread-chunk execution time with 4 or more threads was approximately 395 ms. The control execution time was 539 ms. This is a speedup of 1.36.  

For variable-dimension, since linear transformations make up 7.5% of the runtime, by [Amdahl's Law](#testing-methodology) I'm expecting a maximum speedup of 1.05. As previously, the CPU limits the factor of parallelizability to 4.  

Plot 4 shows how the two schemes perform compared to a single-threaded control run with the same input.  

<img src="https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/LinTrans_Variable.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="700"></img>  

**Plot 4:** *Performance comparison of pthread and pthread-chunk for variable-dimension encryption.*  

Similar to the previous test, the graph illustrates that pthread-chunk performs better pthread, although by a smaller margin. Pthread again performs worse than control when ran single-threaded. The average pthread-chunk execution time with 4 or more threads was approximately 2288 ms. The control execution time was 2401 ms. This is a speedup of 1.05.

In conclusion, the pthread-chunk scheme is the best multithreading scheme for optimizing the performing of linear transformations.  

### Combined Multithreading
After determining that permut-pthread and pthread-chunk were the best schemes for multithreading the generation of permutation matrices and performing linear transformations, respectively, I combined them into a single scheme which will be referred to as permut-pthread-chunk.

For fixed-dimension, taking into account that maxtrix generation (35% runtime) is limited to a factor of parallelizability of 2 and linear transformations (39% of runtime) is limited to a factor of parallelizability of 4, by [Amdahl's Law](#testing-methodology) I'm expecting a maximum speedup of 1.9.  

Plot 5 shows how the two schemes perform independently and combined compared to a single-threaded control run with the same input. Displayed is the elapsed time vs number of threads for 3 passes of fixed-dimension encryption.  

<img src="https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/Combined_Fixed.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="700"></img>  

**Plot 5:** *Performance comparison of permut-thread, pthread-chunk, and permut-pthread-chunk for fixed-dimension encryption.*  

The average permut-pthread-chunk execution time with 4 or more threads was 269 ms. The control execution time was 539 ms. This is a speedup of 2.  

For variable-dimension, taking into account that matrix generation and linear transformations make up 94.5% of the runtime and are both limited to a factor of parallelization of 4, by [Amdahl's Law](#testing-methodology) I'm expecting a maximum speedup of 3.4.  

Plot 6 shows how the two schemes perform independently and combined compared to a single-threaded control run with the same input.  

<img src="https://github.com/kyle2277/C-Permutation-Matrix-Encryption/blob/dev-permut-pthread-and-chunk/Misc/Combined_Variable.png" Alt="Elapsed Time vs Number Threads for Variable-Dimension Encryption" width="700"></img>  

**Plot 6:** *Performance comparison of permut-pthread, pthread-chunk, and permut-pthread-chunk for variable-dimension encryption.*  

The average permut-pthread-chunk execution time with 4 or more threads was 954 ms. The control execution time was 2401 ms. This is a measured speedup of 2.5—around 75% of the ideal speedup, similar to the variable-encryption tests for multithreading only the generation of permutation matrices.  

### Result of Experiments
| Program Section | Multithreading Scheme (dimension) | Calculated Max Speedup | Measured Speedup |
| --------------: | :-------------------- | :--------------------: | :--------------: |
| **Matrix Generation** | permut-pthread (fixed) | 1.2 | 1.3 |
|| permut-pthread (variable) | 2.8 | 2.21 |
| **Linear Transformations** | pthread-chunk (fixed) | 1.4 | 1.36 |
|| pthread-chunk (variable) | 1.05 | 1.05 |
| **Combined** | permut-pthread-chunk (fixed) | 1.9 | 2 |
|| permut-pthread-chunk (variable) | 3.4 | 2.5 |  

**Table 3:** *Comparison of calulated speedups with measured speedups for the multithreading scheme that yielded the best results in each section.*  
#### Analysis  
As shown by Table 3, most of the predicted speedups were fairly consistent with the measured results. The largest outlier was the variable-dimension permut-pthread test, where the measured speedup was approximately 25% below the calculated upper bound. This 25% discrepancy was also present in the variable-dimension permut-pthread-chunk test which suggests that the cause lies within the program, not the data collection method. The issue may be attributable to various things.  

For example, it could've been caused by an incorrect measurement of the amount of the program that is parallelizable in the [single threaded benchmark](#single-threaded-benchmark) test. This would've resulted in an incorrect upper bound calculated by Amdahl's Law. It could've also been caused by the fact that the hyperthreaded CPU used for testing doesn't truly have 4 cores. The factor of parallelizability of 4 that I used in my calculations may have been an overestimation of the actual capability of the CPU in some situations. A third explanation may be that the program's current algorithm for generating permutation matrices is inefficient, since the lacking speedup only occurred in tests where the generation of matrices made up the largest proportion of the program's runtime.  
#### Conclusion  
The least that can be concluded from these experiments is that multithreading both matrix generation and linear transformations provides a speedup of at least 2 to the program. The current version of CPME implements the permut-pthread-chunk multithreading scheme which provide a speedup of approximately 2 and 2.5 for fixed-dimension and variable-dimension encryption, respectively.  

## Endnotes
<sup>1</sup>3Blue1Brown. Linear Transformations and Matrices | Chapter 3, Essence of Linear Algebra. YouTube, YouTube, 7 Aug. 2016, www.youtube.com/watch?v=kYB8IZa5AuE.  
<sup>2</sup>Taboga, Marco. “Permutation Matrix.” StatLect, StatLect, www.statlect.com/matrix-algebra/permutation-matrix.  
<sup>3</sup>Cherlin, Gregory. “Lecture 26 Orthogonal Matrices.” Sites.math.rutgers.edu, Rutgers University, https://sites.math.rutgers.edu/~cherlin/Courses/250/Lectures/250L26.html.  
<sup>4</sup>“Computational Complexity of Mathematical Operations.” Wikipedia, Wikimedia Foundation, 5 July 2021, https://en.wikipedia.org/wiki/Computational_complexity_of_mathematical_operations#Matrix_algebra.  

[Return to table of contents](#documentation-table-of-contents)  
