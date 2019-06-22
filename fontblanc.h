#ifndef FONT_BLANC_C_FONTBLANC_H
#define FONT_BLANC_C_FONTBLANC_H
#include <stdio.h>
#include "Dependencies/csparse.h"

#define LOG_OUTPUT "log.txt"
#define MAPSIZE 1024

typedef enum { false, true } boolean;

struct cipher {
    cs *permut_map[MAPSIZE];
    cs *inv_permut_map[MAPSIZE];
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
void hello(struct cipher *c);
void st_test(void);
cs *lookup(struct cipher *c, int size);

#endif