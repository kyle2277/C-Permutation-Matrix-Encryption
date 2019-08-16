#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H
#include <stdio.h>
#include "Dependencies/csparse.h"

#define LOG_OUTPUT "log.txt"
#define MAPSIZE 1025

typedef enum { false, true } boolean;

// Permutation matrix structure
struct PMAT {
    int dimension;
    struct PMAT_I *i;
    struct PMAT_I *j;
    struct PMAT_V *v;
    double check_vec_bef[1025];
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

typedef struct {
    struct PMAT *permut_map[MAPSIZE];
    struct PMAT *inv_permut_map[MAPSIZE];
    char *log_path;
    char *file_name;
    char *file_path;
    char *encrypt_key;
    int encrypt_key_val;
    long bytes_remaining;
} cipher;

typedef struct node {
    struct node *next;
    struct node *last;
    int number;
} node;

int char_sum(char *s);
int close_cipher(cipher *c);
void purge_mat(struct PMAT *pm);
char **parse_f_path(char *file_path);
cipher create_cipher(char *file_path, char *encrypt_key, long file_length);
int encrypt(cipher *c);
int decrypt(cipher *c);
void fatal(char *log_path, char *message);
char *gen_log_base_str(cipher *c, double log_base);
struct PMAT *gen_permut_mat(cipher *c, int dimension, boolean inverse);
node *next_node(node *last, int dimension);
char charAt(char *ch, int index);
void empty_trash();
int pull_node(boolean row, int count);
double *transform_vec(int dimension, char bytes[], struct PMAT *pm);
struct PMAT *orthogonal_transpose(struct PMAT *mat);
int dot_product(double a[], double b[], int dimension);
struct PMAT *init_permut_mat(int dimension);
void distributor(cipher *c, FILE *in, FILE *out, int coeff);
void permut_cipher(cipher *c, FILE *in, FILE *out, int dimension);
struct PMAT *lookup(cipher *c, int dimension);

#endif