/*
 * fontblanc.h
 * Kyle Won
 * FontBlanc_C core header file.
 */

#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H
#include <stdio.h>
#include "Dependencies/csparse.h"
#include "util.h"

// Changes size of largest possible matrix
#define MAX_DIMENSION 4096
// Increase if crashing ***MUST BE HIGHER THAN MAX DIMENSION***
#define MAPSIZE MAX_DIMENSION + 1
#define ENCRYPT_EXT ".fbz"
#define DECRYPT_TAG "d_"
#define MAX_INSTRUCTIONS 10

// Permutation matrix structure
struct PMAT {
    int dimension;
    struct PMAT_I *i;
    struct PMAT_I *j;
    struct PMAT_V *v;
    double check_vec_bef[MAX_DIMENSION];
    double check_vec_aft[MAX_DIMENSION];
};

// matrix index structure
struct PMAT_I {
    int dimension;
    int icc[]; //row/column indexes
};

//matrix values structure
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

typedef struct cipher{
    struct PMAT **permut_map;
    char *log_path;
    char *file_name;
    char *file_path;
    char encrypt_key[1000];
    int encrypt_key_val;
    long file_len;
    long bytes_remaining;
    long bytes_processed;
    unsigned char *file_bytes;
    instruction **instructions;
    int num_instructions;
    boolean integrity_check;
} cipher;

int key_sum(char *s);
int close_cipher(cipher *c);
void purge_maps(cipher *c);
void purge_mat(struct PMAT *pm);
cipher *create_cipher(char *, char *, long);
void set_instructions(cipher *c, instruction **instructions, int num_instructions);
int run(cipher *c, boolean encrypt);
void read_instructions(cipher *c, int encrypt);
unsigned char* read_input(cipher *c, int coeff);
void write_output(cipher *c, int coeff);
char *gen_linked_vals(cipher *c, int approx);
char *gen_log_base_str(cipher *c, double log_base);
struct PMAT *gen_permut_mat(cipher *c, int dimension, boolean inverse);
double *transform_vec(int dimension, unsigned char bytes[], struct PMAT *pm, boolean integrity_check);
struct PMAT *orthogonal_transpose(struct PMAT *mat);
int dot_product(double a[], double b[], int dimension);
struct PMAT *init_permut_mat(int dimension);
void rand_distributor(cipher *c, int coeff);
void fixed_distributor(cipher *c, int coeff, int dimension);
void permut_cipher(cipher *c, int dimension);
struct PMAT *lookup(cipher *c, int dimension);
// Instructions ------------------------------------------------------------------------------------
instruction *create_instruction(int, char *, boolean);
void print_instructions(instruction **, int);
void clean_instructions(instruction **, int);
void free_instructions(instruction **, int);
#endif