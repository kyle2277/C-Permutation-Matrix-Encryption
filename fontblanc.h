#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H
#include <stdio.h>
#include "Dependencies/csparse.h"

#define LOG_OUTPUT "log.txt"
#define MAPSIZE 1024

typedef enum { false, true } boolean;

// Permutation matrix structure
struct PMAT_I {
    int dimension;
    int icc[]; //row indexes
};

struct PMAT_J {
    int dimension;
    int jcc[]; //column indexes
};

struct PMAT_V {
    int dimension;
    double acc[]; //compressed-column values
};

struct cipher {
    struct PMAT_I *map_i[MAPSIZE];
    struct PMAT_J *map_j[MAPSIZE];
    struct PMAT_V *map_v[MAPSIZE];
    struct PMAT_I *inv_map_i[MAPSIZE];
    struct PMAT_J *inv_map_j[MAPSIZE];
    struct PMAT_V *inv_map_v[MAPSIZE];
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
cs *gen_permut_mat(struct cipher *c, int dimension, boolean inverse);
struct node *next_node(struct node *last, int dimension);
char charAt(char *ch, int index);
int pull_node(boolean row, int count);
//void free_node(struct node *cur);
cs *transform_vec(int dimension, char bytes[], cs *permutation_mat);
void distributor(struct cipher *c, FILE *in, FILE *out, int coeff);
void permut_cipher(struct cipher *c, FILE *in, FILE *out, int dimension);
cs *lookup(struct cipher *c, int size);

#endif