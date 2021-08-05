/*
 * cpme.h
 * Copyrite (c) Kyle Won, 2021
 * FontBlanc_C core header file.
 */

#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H

#include "util.h"

// Changes size of largest possible matrix
#define MAX_DIMENSION 8192
// Increase if crashing ***MUST BE HIGHER THAN MAX DIMENSION***
#define MAPSIZE MAX_DIMENSION + 1
#define ENCRYPT_EXT ".fbz"
#define DECRYPT_TAG "d_"
#define MAX_INSTRUCTIONS 10

/*
 * Permutation matrix structure.
 */
struct PMAT {
    int dimension;
    struct PMAT_I *i;
    struct PMAT_I *j;
    struct PMAT_V *v;
    double *check_vec_bef;
    double *check_vec_aft;
};

/*
 * Matrix index structure.
 */
struct PMAT_I {
    int dimension;
    int icc[]; //row/column indexes
};

/*
 * Matrix values structure.
 */
struct PMAT_V {
    int dimension;
    double acc[]; //compressed column values
};

/*
 * Contains information for one instruction for use by FontBlanc cipher.
 */
typedef struct instruction {
  int dimension;
  boolean integrity_check;
  char *encrypt_key;
} instruction;

/*
 * Cipher structure.
 */
typedef struct cipher{
    struct PMAT **permut_map;
    char *log_path;
    char *file_name;
    char *output_name;
    char *file_path;
    char encrypt_key[1000];
    int encrypt_key_val;
    long file_len;
    _Atomic long bytes_remaining;
    _Atomic long bytes_processed;
    unsigned char *file_bytes;
    instruction **instructions;
    int num_instructions;
    boolean integrity_check;
} cipher;

/*
 * Information for a thread generating a permutation matrix of specified dimension.
 */
typedef struct permut_thread {
  int index;
  int dimension;
  node **trash;
  int trash_index;
  cipher *c;
  boolean inverse;
  // Indicates whether thread should call post on thread counting semaphore and detach upon completion
  boolean post;
} permut_thread;

// Constructors and Destructors --------------------------------------------------------------------
cipher *create_cipher(char *, char *, long, char *);
int close_cipher(cipher *);

// Core operations ---------------------------------------------------------------------------------
int run(cipher *, boolean);
void *variable_thread_func(void *);
void variable_thread_scheduler(cipher *, int);
void *fixed_thread_func(void *);
void fixed_thread_scheduler(cipher *, int, int);
void permut_cipher(cipher *, int, long);

// Matrix operations -------------------------------------------------------------------------------
struct PMAT *init_permut_mat(int);
int pull_node(node **, int, permut_thread *);
void *permut_thread_func(void *);
void gen_variable_permut_mats(cipher *, int);
void gen_fixed_permut_mats(cipher *, int, int);
void gen_permut_mat(permut_thread *);
double *transform_vec(int, unsigned char bytes[], struct PMAT *, boolean);
struct PMAT *orthogonal_transpose(struct PMAT *);
int dot_product(double a[], double b[], int);
void purge_maps(cipher *);
void purge_mat(struct PMAT *);

// Utilities ---------------------------------------------------------------------------------------
int key_sum(char *);
unsigned char* read_input(cipher *);
void write_output(cipher *, int);
char *gen_linked_vals(cipher *, int);
char *gen_log_base_str(cipher *, double);

// Instructions ------------------------------------------------------------------------------------
instruction *create_instruction(int, char *, boolean);
void set_instructions(cipher *, instruction **, int);
void read_instructions(cipher *, int);
void print_instruction_at(instruction **, int);
void print_instructions(instruction **, int);
void print_last_instruction(instruction **, int);
int remove_last_instruction(instruction **, int);
void clean_instructions(instruction **, int);
void free_instructions(instruction **, int);
#endif
