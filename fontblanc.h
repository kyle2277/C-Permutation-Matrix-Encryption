#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H
#include <stdio.h>
#include "Dependencies/csparse.h"

#define LOG_OUTPUT "log.txt"
#define MAPSIZE 1024

typedef enum { false, true } boolean;

// Permutation matrix structure
struct PMAT {
    int dimension;
    struct PMAT_I *i;
    struct PMAT_I *j;
    struct PMAT_V *v;
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

struct cipher {
    struct PMAT *permut_map[MAPSIZE];
    struct PMAT *inv_permut_map[MAPSIZE];
    char *log_path;
    char *file_name;
    char *file_path;
    char *encrypt_key;
    int encrypt_key_val;
    long bytes_remainging;
};

struct node {
    struct node *next;
    struct node *last;
    int number;
};

int char_sum(char *s);
int close_cipher(struct cipher *c);
char **parse_f_path(char *file_path);
struct cipher create_cipher(char *file_path, char *encrypt_key, long file_length);
int encrypt(struct cipher *c);
int decrypt(struct cipher *c);
void fatal(char *log_path, char *message);
char *gen_log_base_str(struct cipher *c, double log_base);
struct PMAT *gen_permut_mat(struct cipher *c, int dimension, boolean inverse);
struct node *next_node(struct node *last, int dimension);
char charAt(char *ch, int index);
int pull_node(boolean row, int count);
//void free_node(struct node *cur);
double *transform_vec(int dimension, char bytes[], struct PMAT *pm);
void distributor(struct cipher *c, FILE *in, FILE *out, int coeff);
void permut_cipher(struct cipher *c, FILE *in, FILE *out, int dimension);
struct PMAT *lookup(struct cipher *c, int size);

#endif