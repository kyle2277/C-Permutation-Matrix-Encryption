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

#define ENCRYPT_TAG "e_"
#define ENCRYPT_EXT ".txt"
#define DECRYPT_TAG "d_"
clock_t time_total_gen;
clock_t time_total_write;
clock_t time_transformation;
clock_t time_p_loop;
node *i_head, *j_head;
node *trash[MAX_DIMENSION*2];
int trash_indx;

/*
 * Create a cipher structure for the given file with the given encryption key
 * Returns the cipher structure
 */
cipher create_cipher(char *file_in_path, long file_length, instruction **instructions, int num_instructions) {
    long bytes_remaining = file_length;
    char **processed = parse_f_path(file_in_path);
    char *file_name = processed[0];
    char *just_path = processed[1];
    char *log_path = LOG_OUTPUT;
    //cipher *c = (cipher *)malloc(sizeof(*c)+sizeof(int *)*len_instructions);
    cipher c = {.permut_map={}, .inv_permut_map={}, .log_path=log_path, .file_name=file_name,
            .file_path=just_path, .file_len=file_length, .bytes_remaining=bytes_remaining,
            .bytes_processed=0, .instructions=instructions, .num_instructions=num_instructions};
    free(processed);
    return c;
}

/*
 * Run the process. Takes cipher and whether tp encrypt or not
 */
int run(cipher *c, boolean encrypt) {
    int coeff = encrypt ? 1 : -1;
    time_total_gen = 0;
    time_total_write = 0;
    time_transformation = 0;
    time_p_loop = 0;
    unsigned char *file_bytes = read_input(c, coeff);
    c->file_bytes = file_bytes;
    read_instructions(c, coeff);
    write_output(c, coeff);
    printf("Time generating permutation matrices (ms): %.2lf\n", (double)time_total_gen*1000/CLOCKS_PER_SEC);
    printf("Time writing matrices to file (ms): %.2lf\n", (double)time_total_write*1000/CLOCKS_PER_SEC);
    printf("Time performing linear transformation (ms): %.2lf\n", (double)time_transformation*1000/CLOCKS_PER_SEC);
    printf("Time in node pull loop (ms): %.2lf\n", (double)time_p_loop*1000/CLOCKS_PER_SEC);
    return 1;
}

//DEPRECATED
int encrypt(cipher *c) {
    int coeff = 1; //internally denotes encryption
    time_total_gen = 0;
    time_total_write = 0;
    time_transformation = 0;
    time_p_loop = 0;
    unsigned char *file_bytes = read_input(c, coeff);
    c->file_bytes = file_bytes;
    read_instructions(c, coeff);
    write_output(c, coeff);
    printf("Time generating permutation matrices (ms): %.2lf\n", (double)time_total_gen*1000/CLOCKS_PER_SEC);
    printf("Time writing matrices to file (ms): %.2lf\n", (double)time_total_write*1000/CLOCKS_PER_SEC);
    printf("Time performing linear transformation (ms): %.2lf\n", (double)time_transformation*1000/CLOCKS_PER_SEC);
    printf("Time in node pull loop (ms): %.2lf\n", (double)time_p_loop*1000/CLOCKS_PER_SEC);
    return 1;
}

//DEPRECATED
int decrypt(cipher *c) {
    int coeff = -1; //internally denotes decryption
    time_total_gen = 0;
    time_total_write = 0;
    time_transformation = 0;
    time_p_loop = 0;
    unsigned char *file_bytes = read_input(c, coeff);
    c->file_bytes = file_bytes;
    read_instructions(c, coeff);
    write_output(c, coeff);
    printf("Time generating permutation matrices (ms): %.2lf\n", (double)time_total_gen*1000/CLOCKS_PER_SEC);
    printf("Time writing matrices to file (ms): %.2lf\n", (double)time_total_write*1000/CLOCKS_PER_SEC);
    printf("Time performing linear transformation (ms): %.2lf\n", (double)time_transformation*1000/CLOCKS_PER_SEC);
    printf("Time in node pull loop (ms): %.2lf\n", (double)time_p_loop*1000/CLOCKS_PER_SEC);
    return 1;
}

/*
 * Iterates through the instructions
 */
void read_instructions(cipher *c, int coeff) {
    int num_instructions = c->num_instructions;
    int a;
    int b;
    if(coeff > 0) { //encrypt, read instructions forwards
        a = 0;
        b = num_instructions;
    } else { //coeff < 0, decrypt, read instructions backwards
        a = -1 * (num_instructions-1);
        b = 1;
    }
    //iterate through instructions
    for(int i = a; i < b; i++) {
        instruction *cur = c->instructions[abs(i)];
        c->bytes_remaining = c->file_len;
        c->bytes_processed = 0;
        int dimension = cur->dimension;
        size_t key_len = strlen(cur->encrypt_key);
        memcpy(c->encrypt_key, cur->encrypt_key, sizeof(char)*key_len);
        memset(cur->encrypt_key, '\0', sizeof(char)*key_len);
        c->encrypt_key_val = char_sum(c->encrypt_key);
        if(dimension > 0) { //fixed dimension
            fixed_distributor(c, coeff, dimension);
        } else { //flexible dimension
            rand_distributor(c, coeff);
        }
        purge_maps(c);
        memset(c->encrypt_key, '\0', sizeof(char)*key_len);
        c->encrypt_key_val = 0;
    }
}

/*
 * Takes cipher object and whether encrypt or decrypt
 * Reads entire file into the program
 */
unsigned char* read_input(cipher *c, int coeff) {
    long file_len = c->file_len;
    FILE *in;
    char *f_in_path = (char *)malloc(sizeof(char)*256);
    if(coeff > 0) { //encrypt
        sprintf(f_in_path, "%s%s", c->file_path, c->file_name);
    } else { //decrypt
        sprintf(f_in_path, "%s%s%s%s", c->file_path, ENCRYPT_TAG, c->file_name, ENCRYPT_EXT);
    }
    in = fopen(f_in_path, "r");
    unsigned char *file_bytes = (unsigned char *)malloc(sizeof(unsigned char)*file_len);
    fread(file_bytes, 1, (size_t)file_len, in);
    free(f_in_path);
    fclose(in);
    return file_bytes;
}

/*
 * Writes encrypted/decrypted data to file
 */
void write_output(cipher *c, int coeff) {
    long file_len = c->file_len;
    FILE *out;
    char *f_out_path = (char *)malloc(sizeof(char)*256);
    if(coeff > 0) { //encrypt
        sprintf(f_out_path, "%s%s%s%s", c->file_path, ENCRYPT_TAG, c->file_name, ENCRYPT_EXT);
    } else { //decrypt
        sprintf(f_out_path, "%s%s%s", c->file_path, DECRYPT_TAG, c->file_name);
    }
    out = fopen(f_out_path, "w");
    fwrite(c->file_bytes, 1, (size_t)file_len, out);
    free(f_out_path);
    fclose(out);
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
    exit(1);
}

/*
 * Delete a cipher structure
 */
int close_cipher(cipher *c) {
    //todo segfault when free file_name
    free(c->file_path);
    free(c->instructions);
    free(c->file_bytes);
    return 1;
}

/*
 * zero out permutation matrix maps
 */
void purge_maps(cipher *c) {
    boolean n_inv;
    boolean inv;
    for(int i = 0; i < MAPSIZE; i++) {
        struct PMAT *pm = c->permut_map[i];
        struct PMAT *t_pm = c->inv_permut_map[i];
        n_inv = pm != NULL;
        inv = t_pm != NULL;
        if(n_inv) {
            purge_mat(pm);
            c->permut_map[i] = NULL;
        } else if(inv) {
            purge_mat(t_pm);
            c->inv_permut_map[i] = NULL;
        }
    }
}

/*
 * Zero out contents of matrix
 */
void purge_mat(struct PMAT *pm) {
    memset(pm->i->icc, '\0', pm->dimension*sizeof(int));
    memset(pm->j->icc, '\0', (pm->dimension+1)*sizeof(int));
    memset(pm->v->acc, '\0', pm->dimension*sizeof(double));
    memset(pm->check_vec_bef, '\0', pm->dimension*sizeof(double));
    memset(pm->check_vec_aft, '\0', pm->dimension*sizeof(double));
    memset(&pm->dimension, '\0', sizeof(int));
    free(pm);
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
    char *linked = gen_linked_vals(c, 2*dimension);
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
        m->check_vec_bef[j_val] = (double) j_val;
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
    //create vector to check integrity of data
    double *check_vec = cc_mv(dimension, dimension, dimension, resultant_m->i->icc, resultant_m->j->icc,
            resultant_m->v->acc, resultant_m->check_vec_bef);
    memcpy(resultant_m->check_vec_aft, check_vec, sizeof(double)*dimension);
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
        next->next = next_node(next, dimension);
        return next;
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
    int dot_bef = dot_product(vec, pm->check_vec_bef, dimension);
    double *result = cc_mv(dimension, dimension, dimension, pm->i->icc, pm->j->icc, pm->v->acc, vec);
    int dot_aft = dot_product(result, pm->check_vec_aft, dimension);
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
    memcpy(t_m->check_vec_bef, mat->check_vec_bef, sizeof(double)*dimension);
    return t_m;
}

/*
 * Takes two column vectors and their dimension
 * Returns the dot product
 */
int dot_product(double a[], double b[], int dimension) {
    double result = 0;
    for(int i = 0; i < dimension; i++) {
        result += a[i] * b[i];
    }
    return (int) result;
}

/*
 * Allocate space for a matrix object
 */
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

/*
 * process file using pseudo-random matrix dimensions
 */
void rand_distributor(cipher *c, int coeff) {
    //FILE *dim_vals = fopen("dim_vals.csv", "w");
    //create encrypt map of length required for file instead of looping
    int approx = (int)c->bytes_remaining/MAX_DIMENSION;
    char *linked = gen_linked_vals(c, approx);
    int map_len = (int)strlen(linked);
    for(int map_itr = 0; c->bytes_remaining >= MAX_DIMENSION; map_itr++) {
        //todo improve dimension randomization
        int tmp = (charAt(linked, map_itr % map_len) - '0');
        int dimension = tmp > 1 ? MAX_DIMENSION - (MAX_DIMENSION/tmp) : MAX_DIMENSION;
//        char *write = (char *)malloc(sizeof(char)*110);
//        sprintf(write, "%d\n", dimension);
//        fwrite(write, sizeof(char), strlen(write), dim_vals);
//        free(write);
        permut_cipher(c, coeff*dimension);
    }
    //todo limits file size to max size of int in bytes, ~2GB
    int b = (int) c->bytes_remaining;
    if(b > 0) {
        permut_cipher(c, coeff*b);
    }
    free(linked);
//    fclose(dim_vals);
}

/*
 * Process file using a fixed matrix dimension
 */
void fixed_distributor(cipher *c, int coeff, int dimension) {
    while(c->bytes_remaining >= dimension) {
        permut_cipher(c, coeff*dimension);
    }
    int b = (int)c->bytes_remaining;
    if(b > 0) {
        permut_cipher(c, coeff*b);
    }
}

/*
 * Generates a string of pseudo-random values of length provided
 */
 char *gen_linked_vals(cipher *c, int approx) {
    int sequences = 1;
    if(approx > 15) {
        sequences = ((approx - (approx%15))/15) + 1;
    }
    //16 is the number of values in the log string
    char *linked = (char *)calloc((size_t)16*sequences, sizeof(char));
    //create string used to choose permutation matrix
    for(int i = 0; i < sequences; i++) {
        //i + dimension = log base
        char *logBaseOutput = gen_log_base_str(c, (i+approx));
        sprintf(linked, "%s%s", linked, logBaseOutput);
        free(logBaseOutput);
    }
    return linked;
}

/*
 * Facilitates matrix tranformations
 */
void permut_cipher(cipher *c, int dimension) {
    long ref = c->bytes_processed;
    char *data = c->file_bytes;
    struct PMAT *pm = lookup(c, dimension);
    boolean inverse = dimension < 0;
    dimension = abs(dimension);
    struct PMAT *permutation_mat = pm ? pm : gen_permut_mat(c, dimension, inverse);
    char *data_in = (char *)malloc(sizeof(char)*dimension);
    memcpy(data_in, data+ref, (size_t)dimension);
    double *result = transform_vec(dimension, data_in, permutation_mat);
    double *ptr = result;
    unsigned char *data_result = (unsigned char *)malloc(sizeof(unsigned char)*dimension);
    for(int i = 0; i < dimension; i++, ptr++) {
        data_result[i] = (unsigned char)*ptr;
    }
    //check for data preservation error
    if(result == NULL) {
        char *message = (char *)malloc(sizeof(char)*256);
        sprintf(message, "%s\n%ld%s\n%s\n", "Corruption detected in encryption.", c->bytes_remaining,
                " unencrypted bytes remaining.", "Aborting.");
        fatal(c->log_path, message);
        exit(1);
    }
    memcpy(data+ref, data_result, (size_t)dimension);
    free(data_in);
    c->bytes_processed += dimension;
    c->bytes_remaining -= dimension;
}

/*
 * Takes matrix dimension
 * Returns corresponding matrix object if exists
 */
struct PMAT *lookup(cipher *c, int dimension) {
    return dimension < 0 ? c->inv_permut_map[abs(dimension)] : c->permut_map[abs(dimension)];
}

/*
 * Create an instruction to add to the cipher instructions array. Takes whether the array dimensions should be fixed
 * (0 = random dimensions, >=1 = fixed dimension) and the dimension (if fixed)
 * Returns an array of instructions
 */
instruction *create_instruction(int dimension, char encrypt_key[]) {
    instruction *i = (instruction *)malloc(sizeof(instruction) + sizeof(char)*strlen(encrypt_key));
    i->dimension = dimension;
    memcpy(i->encrypt_key, encrypt_key, sizeof(char)*strlen(encrypt_key));
    return i;
}