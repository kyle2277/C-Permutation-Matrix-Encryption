#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H
#include <stdio.h>
#include "Dependencies/csparse.h"

#define LOG_OUTPUT "log.txt"
//Increase if crashing ***MUST BE HIGHER THAN MAX DIMENSION***
#define MAPSIZE 1025
//Changes size of largest possible matrix
#define MAX_DIMENSION 1024
#define ENCRYPT_TAG "e_"
#define ENCRYPT_EXT ".fbz"
#define DECRYPT_TAG "d_"

typedef enum { false, true } boolean;

// Permutation matrix structure
struct PMAT {
    int dimension;
    struct PMAT_I *i;
    struct PMAT_I *j;
    struct PMAT_V *v;
    double check_vec_bef[MAX_DIMENSION];
    double check_vec_aft[];
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

typedef struct instruction {
    int dimension;
    char encrypt_key[];
} instruction;

typedef struct {
    struct PMAT *permut_map[MAPSIZE];
    struct PMAT *inv_permut_map[MAPSIZE];
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
} cipher;

typedef struct node {
    struct node *next;
    struct node *last;
    int number;
} node;


int key_sum(char *s);
int close_cipher(cipher *c);
void purge_maps(cipher *c);
void purge_mat(struct PMAT *pm);
char **parse_f_path(char *file_path);
cipher create_cipher(char *file_name, char *just_path, long file_length);
long get_f_len(char *file_path);
void set_instructions(cipher *c, instruction **instructions, int num_instructions);
int run(cipher *c, boolean encrypt);
int encrypt(cipher *c);
int decrypt(cipher *c);
void read_instructions(cipher *c, int encrypt);
unsigned char* read_input(cipher *c, int coeff);
void write_output(cipher *c, int coeff);
void fatal(char *log_path, char *message);
char *gen_log_base_str(cipher *c, double log_base);
struct PMAT *gen_permut_mat(cipher *c, int dimension, boolean inverse);
node *next_node(node *last, int dimension);
char charAt(char *ch, int index);
void empty_trash();
int pull_node(boolean row, int count);
double *transform_vec(int dimension, unsigned char bytes[], struct PMAT *pm);
struct PMAT *orthogonal_transpose(struct PMAT *mat);
int dot_product(double a[], double b[], int dimension);
struct PMAT *init_permut_mat(int dimension);
char *gen_linked_vals(cipher *c, int approx);
void rand_distributor(cipher *c, int coeff);
void fixed_distributor(cipher *c, int coeff, int dimension);
void permut_cipher(cipher *c, int dimension);
struct PMAT *lookup(cipher *c, int dimension);
instruction *create_instruction(int dimension, char *encryptKey);

#endif