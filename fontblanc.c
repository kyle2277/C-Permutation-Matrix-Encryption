#include "fontblanc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "fontblanc.h"
#include "Dependencies/csparse.h"
#include "Dependencies/st_io.h"
#include "Dependencies/st_to_cc.h"

//todo dot product check for data preservation, a dot b = Qa dot Qb

#define ENCRYPT_TAG "e_"
#define ENCRYPT_EXT ".txt"
#define DECRYPT_TAG "d_"
clock_t time_total_gen;
clock_t time_total_write;
clock_t time_transformation;
clock_t time_p_loop;
node *i_head, *j_head;
node *trash[2048];
int trash_indx;

/*
 * Create a cipher structure for the given file with the given encryption key
 * Returns the cipher structure
 */
cipher create_cipher(char *file_path, char *encrypt_key, long file_length) {
    int encrypt_key_val = char_sum(encrypt_key);
    long bytes_remaining = file_length;
    char **processed = parse_f_path(file_path);
    char *file_name = processed[0];
    char *just_path = processed[1];
    char *log_path = LOG_OUTPUT;
    cipher c = {.permut_map={}, .inv_permut_map={}, .log_path=log_path, .file_name=file_name,
            .file_path=just_path, .encrypt_key=encrypt_key, .encrypt_key_val=encrypt_key_val,
            .bytes_remaining=bytes_remaining};
    free(processed);
    return c;
}

int encrypt(cipher *c) {
    time_total_gen = 0;
    time_total_write = 0;
    time_transformation = 0;
    time_p_loop = 0;
    char *f_in_path = (char *)malloc(sizeof(char)*256);
    sprintf(f_in_path, "%s%s", c->file_path, c->file_name);
    FILE *in = fopen(f_in_path, "r");
    char *f_out_path = (char *)malloc(sizeof(char)*256);
    sprintf(f_out_path, "%s%s%s%s", c->file_path, ENCRYPT_TAG, c->file_name, ENCRYPT_EXT);
    FILE *out = fopen(f_out_path, "w");
    distributor(c, in, out, 1);
    printf("Time generating permutation matrices (ms): %.2lf\n", (double)time_total_gen*1000/CLOCKS_PER_SEC);
    printf("Time writing matrices to file (ms): %.2lf\n", (double)time_total_write*1000/CLOCKS_PER_SEC);
    printf("Time performing linear transformation (ms): %.2lf\n", (double)time_transformation*1000/CLOCKS_PER_SEC);
    printf("Time in node pull loop (ms): %.2lf\n", (double)time_p_loop*1000/CLOCKS_PER_SEC);
    free(f_in_path);
    free(f_out_path);
    fclose(in);
    fclose(out);
    return 1;
}

int decrypt(cipher *c) {
    char *f_in_path = (char *)malloc(sizeof(char)*256);
    sprintf(f_in_path, "%s%s%s%s", c->file_path, ENCRYPT_TAG, c->file_name, ENCRYPT_EXT);
    FILE *in = fopen(f_in_path, "r");
    char *f_out_path = (char *)malloc(sizeof(char)*256);
    sprintf(f_out_path, "%s%s%s", c->file_path, DECRYPT_TAG, c->file_name);
    FILE *out = fopen(f_out_path, "w");
    distributor(c, in, out, -1);
    free(f_in_path);
    free(f_out_path);
    fclose(in);
    fclose(out);
    return 1;
}

void fatal(char *log_path, char *message) {
    time_t curtime = time(NULL);
    struct tm *loctime = localtime(&curtime);
    char *out = (char *)malloc(sizeof(char)*256);
    sprintf(out, "\n%s%s\n", asctime(loctime), message);
    FILE* log = fopen(log_path, "a");
    printf("\nFATAL: %s\n", out);
    fwrite(out, sizeof(char), strlen(out), log);
    free(out);
    fclose(log);
}

/*
 * Delete a cipher structure
 */
int close_cipher(cipher *c) {
    //todo segfault when free file_name
    free(c->file_path);
    return 1;
}

/*
 * Separates the file path from the file name
 * Returns file name and file path up to the name
 */
char **parse_f_path(char *file_path) {
    //allocate double pointer to store returned file vals
    char **processed = (char **)malloc(sizeof(char *)*2);
    processed[0] = (char *)malloc(sizeof(char)*256);
    processed[1] = (char *)malloc(sizeof(char)*256);
    size_t path_len = strlen(file_path);
    char *ptr = file_path + path_len;
    int name_len;
    for(name_len = 0; *(ptr-1) != '/'; name_len++) {
        ptr--;
    }
    char *f_name = ptr;
    printf("File name: %s\n", f_name);
    size_t keep = path_len - name_len;
    char *just_path = (char *)malloc(sizeof(char)*keep+1);
    strncpy(just_path, file_path, keep);
    processed[0] = f_name;
    processed[1] = just_path;
    return processed;
}

/*
 * Returns the sum of the char values of a char array
 */
int char_sum(char *s) {
    int sum;
    for(sum = 0; *s != '\0'; s++) {
        sum += *s;
    }
    return sum;
}

/*
 * Generates unique, pseudo-random string of numbers using the encryption key
 */
char *gen_log_base_str(cipher *c, double log_base) {
    double output = log(c->encrypt_key_val)/log(log_base);
    char *log_base_str = (char *)calloc(64, sizeof(char));
    sprintf(log_base_str, "%.15lf", output);
    while(*log_base_str != '.') {
        log_base_str++;
    }
    log_base_str++;
    char *final_output = (char *)malloc(sizeof(char)*strlen(log_base_str));
    strcpy(final_output, log_base_str);
//    printf("%s\n", log_base_str);
    return final_output;
}

/*
 * Takes the dimension of the matrix to create (dimension is negative if inverse)
 * Generates unique n-dimensional permutation matrices from the encryption key
 */
struct PMAT *gen_permut_mat(cipher *c, int dimension, boolean inverse) {
    clock_t start = clock();
    int sequences = 1;
    if(2*dimension > 15) {
        sequences = (((2*dimension) - ((2*dimension)%15))/15) + 1;
    }
    char *linked = (char *)calloc((size_t)15*dimension, sizeof(char));
    //create string used to choose permutation matrix
    for(int i = 0; i < sequences; i++) {
        //i + dimension = log base
        char *logBaseOutput = gen_log_base_str(c, (i+dimension));
        sprintf(linked, "%s%s", linked, logBaseOutput);
        free(logBaseOutput);
    }
    //create linked lists used to build matrices
    i_head = (node *)malloc(sizeof(node));
    i_head->last = NULL;
    i_head->number = 0;
    //{.next = NULL, .last = NULL, .number = 0};
    i_head->next = next_node(i_head, dimension);
    j_head = (node *)malloc(sizeof(node));
    //{.next = NULL, .last = NULL, .number = 0};
    j_head->last = NULL;
    j_head->number = 0;
    j_head->next = next_node(j_head, dimension);
    //create permutation matrix
    double acc[dimension];
    int icc[dimension];
    int jcc[dimension+1];
    struct PMAT *m = init_permut_mat(dimension);
//    FILE *f_vals = fopen("pmat_vals.csv", "w");
    int dimension_counter = 0;
    int list_len = dimension;
    clock_t p_loop = clock();
    int i_val;
    int j_val;
    trash_indx = 0;
    for(int k = 0; k < 2*dimension; k+=2) {
        acc[dimension_counter] = 1.0;
        if(list_len == 1) {
            i_val = i_head->number;
            j_val = j_head->number;
        } else {
            int row = (charAt(linked, k)-'0');
            row = ((row+1) * dimension) % list_len;
            i_val = pull_node(true, row);
            int column = (charAt(linked, k + 1)-'0');
            column = ((column+1) * dimension) % list_len;
            j_val = pull_node(false, column);
//            char *write = (char *)malloc(sizeof(char)*120);
//            sprintf(write, "%d,%d\n", i_val, j_val);
//            fwrite(write, sizeof(char), strlen(write), f_vals);
//            free(write);
            dimension_counter++;
            list_len--;
        }
        //put index values in array using compressed-column format
        //row index values in order by column
        icc[j_val] = i_val;
        //column indexes
        jcc[j_val] = j_val;
        m->check_vec[j_val] = (double)j_val;
    }
    //todo segfault without this line????
    jcc[dimension] = dimension;
    clock_t p_loop_diff = clock() - p_loop;
    time_p_loop += p_loop_diff;
//    fclose(f_vals);
    clock_t difference = clock() - start;
    time_total_gen += difference;
    free(linked);
    free(i_head);
    free(j_head);
    empty_trash();
    //put permutation matrix in cipher dictionary
    clock_t start_write = clock();
    memcpy(m->i->icc, icc, sizeof(int)*dimension);
    memcpy(m->j->icc, jcc, sizeof(int)*(dimension+1));
    memcpy(m->v->acc, acc, sizeof(double)*dimension);
    struct PMAT *resultant_m;
    if(inverse) {
        resultant_m = orthogonal_transpose(m);
        c->inv_permut_map[dimension] = resultant_m;
    } else {
        resultant_m = m;
        c->permut_map[dimension] = resultant_m;
    }
    clock_t diff_write = clock() - start_write;
    time_total_write += diff_write;
    //printf("created mat, %d\n", dimension);
    return resultant_m;
//    return inverse ? cs_transpose(permut_matrix, dimension) : permut_matrix;
}

char charAt(char *ch, int index) {
    char *ptr = ch;
    ptr = ptr + index;
    return *ptr;
}

void empty_trash() {
    for(int i = 0; i < trash_indx; i++) {
        if(trash[i]) {
            free(trash[i]);
        }
    }
}

/*
 * Recursively creates new nodes until the correct length has been reached
 */
node *next_node(node *last, int dimension) {
    node *next = (node *)malloc(sizeof(node));
    if(last->number == dimension - 1) {
        return NULL;
    } else {
        next->last = last;
        next->number = last->number +1;
        //next = {.next = NULL, .last = last, .number = last->number+1};
        next->next = next_node(next, dimension);
        return next;
//        next.next = (struct node *)malloc(sizeof(struct node));
//        next.last = (struct node *)malloc(sizeof(struct node));
//        next.last = last;
//        next.number = last->number + 1;
//        next.next = next_node(next, dimension);

    }
}

/*
 * Fetches a node from the given linked list and deletes node from the list
 * Takes whether the list is the row or column list and the node index
 * Returns the number corresponding to the node in question
 */
int pull_node(boolean row, int count) {
    node *cur = row ? i_head : j_head;
    for(int i = count; i > 1; i--) {
        cur = cur->next;
    }
    int num = cur->number;
    if(!cur->last && cur->next) { //first node in list
        if(row) {
            i_head = i_head->next;
            i_head->last = NULL;
        } else {
            j_head = j_head->next;
            j_head->last = NULL;
        }
    } else if(!cur->next && cur->last) { //last node in list
        cur->last->next = NULL;
    } else { //middle node in list
        cur->last->next = cur->next;
        cur->next->last = cur->last;
    }
    //free the node later
    trash[trash_indx] = cur;
    trash_indx++;
    return num;
}

/*
 * Takes the matrix dimension, a list of bytes from the file and relevant permutation matrix
 * Performs the linear transformation operation on the byte vector and returns the resulting vector
 */
double *transform_vec(int dimension, char bytes[], struct PMAT *pm) {
    double vec[dimension];
    for(int i = 0; i < dimension; i++) {
        vec[i] = bytes[i];
    }
    clock_t transform_start = clock();
    int dot_bef = dot_product(vec, pm->check_vec, dimension);
    double *result = cc_mv(dimension, dimension, dimension, pm->i->icc, pm->j->icc, pm->v->acc, vec);
    double *check_result = cc_mv(dimension, dimension, dimension, pm->i->icc, pm->j->icc, pm->v->acc, pm->check_vec);
    int dot_aft = dot_product(result, check_result, dimension);
    clock_t transform_diff = clock() - transform_start;
    time_transformation += transform_diff;
    return dot_bef == dot_aft ? result : NULL;
}

/*
 * Takes an orthogonal matrix object and transposes it (equal to the matrix inverse)
 * Returns the resulting matrix object
 */
struct PMAT *orthogonal_transpose(struct PMAT *mat) {
    int dimension = mat->dimension;
    struct PMAT *t_m = init_permut_mat(dimension);
    //switch row and column arrays
    int *new_icc = mat->j->icc;
    int *new_jcc = mat->i->icc;
    int t_icc[dimension];
    int t_jcc[dimension+1];
    for(int i = 0; i < dimension; i++) {
        t_jcc[new_jcc[i]] = new_jcc[i];
        t_icc[new_jcc[i]] = new_icc[i];
    }
    t_jcc[dimension] = dimension;
    memcpy(t_m->i->icc, t_icc, sizeof(int)*dimension);
    memcpy(t_m->j->icc, t_jcc, sizeof(int)*(dimension+1));
    memcpy(t_m->v->acc, mat->v->acc, sizeof(double)*dimension);
    memcpy(t_m->check_vec, mat->check_vec, sizeof(double)*dimension);
    return t_m;
}

int dot_product(double a[], double b[], int dimension) {
    double result = 0;
    for(int i = 0; i < dimension; i++) {
        result += a[i] * b[i];
    }
    return (int) result;
}

struct PMAT *init_permut_mat(int dimension) {
    //initialize new matrix object
    struct PMAT_I *mi = (struct PMAT_I *)malloc(sizeof(*mi) + sizeof(int)*dimension);
    //size is N columns + 1 as required by cc_mv matrix multiplication
    struct PMAT_I *mj = (struct PMAT_I *)malloc(sizeof(*mj) + sizeof(int)*(dimension+1));
    struct PMAT_V *mv = (struct PMAT_V *)malloc(sizeof(*mv) + sizeof(double)*dimension);
    struct PMAT *m = (struct PMAT *)malloc(sizeof(*m) + sizeof(struct PMAT_I) + sizeof(int)*dimension
            + sizeof(struct PMAT_I) + sizeof(int)*(dimension+1) + sizeof(struct PMAT_V) + sizeof(double)*dimension);
    m->dimension = dimension;
    m->i = mi;
    m->j = mj;
    m->v = mv;
    return m;
}

void distributor(cipher *c, FILE *in, FILE *out, int coeff) {
    char *encrypt_map = gen_log_base_str(c, exp(1));
    //create encrypt map of length required for file instead of looping
    int map_len = (int)strlen(encrypt_map);
    for(int map_itr = 0; c->bytes_remaining > 1024; map_itr++) {
        if(map_itr == map_len) {
            map_itr = 0;
        }
        //todo improve dimension randomization
        int tmp = (charAt(encrypt_map, map_itr) - '0') + 1;
        int dimension = 1024/tmp;
        permut_cipher(c, in, out, coeff*dimension);
//        permut_cipher(c, in, out, coeff*1024);
    }
    //todo limits file size to max size of int in bytes, ~2GB
    int b = (int) c->bytes_remaining;
    if(b > 0) {
        permut_cipher(c, in, out, coeff*b);
    }
    free(encrypt_map);
}

void permut_cipher(cipher *c, FILE *in, FILE *out, int dimension) {
    struct PMAT *pm = lookup(c, dimension);
    boolean inverse = dimension < 0;
    dimension = abs(dimension);
    struct PMAT *permutation_mat = pm ? pm : gen_permut_mat(c, dimension, inverse);
    char *data_in = (char *)malloc(sizeof(char)*dimension);
    fread(data_in, 1, (size_t)dimension, in);
    double *result = transform_vec(dimension, data_in, permutation_mat);
    //check for data preservation error
    if(result == NULL) {
        char *message = (char *)malloc(sizeof(char)*256);
        sprintf(message, "%s\n%ld%s\n%s\n", "Corruption detected in encryption.", c->bytes_remaining,
                " unencrypted bytes remaining.", "Aborting.");
        fatal(c->log_path, message);
        exit(1);
    }
    //parse result, done w/ coefficient value
    unsigned char *byte_data = (unsigned char *) calloc((size_t)dimension, sizeof(unsigned char));
    double *byte_ptr = result;
    //optimize double --> int --> unsigned char
    for(int i = 0; i < dimension; i++) {
        byte_data[i] = (unsigned char)*byte_ptr;
        //printf("%d\n", byte_data[i]);
        byte_ptr++;
    }
    fwrite(byte_data, 1, (size_t)dimension, out);
    free(data_in);
    free(byte_data);
    c->bytes_remaining -= dimension;
}

struct PMAT *lookup(cipher *c, int dimension) {
    return dimension < 0 ? c->inv_permut_map[abs(dimension)] : c->permut_map[abs(dimension)];
}


