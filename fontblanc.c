#include "fontblanc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "fontblanc.h"
#include "Dependencies/csparse.h"
#include "Dependencies/st_io.h"

#define ENCRYPT_TAG "safe_"
#define ENCRYPT_EXT ".fbc"
int size = 2;
struct node *i_head, *j_head;

/*
 * Create a cipher structure for the given file with the given encryption key
 * Returns the cipher structure
 */
struct cipher create_cipher(char *file_path, char *file_name, char *encrypt_key, long file_length) {
    int encrypt_key_val = char_sum(encrypt_key);
    long bytes_remaining = file_length;
    char *path = rem_file_f_path(file_path, file_name);
    char *log_path = LOG_OUTPUT;
    struct cipher c = {.permut_map={}, .log_path=log_path, .file_name=file_name, .file_path=path,
            .encrypt_key=encrypt_key, .encrypt_key_val=encrypt_key_val, .bytes_remainging=bytes_remaining};
    return c;
}

int encrypt(struct cipher *c) {
    char absolute_path[256];
    sprintf(absolute_path, "%s%s%s%s", c->file_path, ENCRYPT_TAG, c->file_name, ENCRYPT_EXT);
    return 1;
}

int decrypt(struct cipher *c) {
    return 1;
}


/*
 * Delete a cipher structure
 */
int close_cipher(struct cipher *c) {
    free(c->file_path);
    return 1;
}

/*
 * Separates the file path from the file name
 * Returns a pointer to the path
 */
char *rem_file_f_path(char *file_path, char *file_name) {
    size_t len_keep = strlen(file_path) - strlen(file_name);
    printf("Full path: %s\n", file_path);
    char *path = malloc(256);
    strncpy(path, file_path, len_keep);
    printf("Just path: %s\n", path);
    return path;
}

/*
 * Returns the sum of the char values of a char array
 */
int char_sum(char *s) {
    int sum = 0;
    char *ptr = s;
    while(*ptr != '\0') {
        sum += *ptr;
        ptr++;
    }
    printf("%d\n", sum);
    return sum;
}

/*
 * Generates unique, pseudo-random string of numbers using the encryption key
 */
char *gen_log_base_str(struct cipher *c, double log_base) {
    double output = log(c->encrypt_key_val)/log(log_base);
    char *log_base_str = malloc(256);
    sprintf(log_base_str, "%.15lf", output);
    printf("%s\n", log_base_str);
    char *final_output = malloc(256);
    for(char *ptr = log_base_str; *ptr != '\0'; ptr++) {
        if(*ptr != '.') {
            strncat(final_output, ptr, 1);
        }
    }
    printf("%s\n", final_output);
    free(log_base_str);
    return final_output;
}

/*
 * Takes the dimension of the matrix to create (dimension is negative if inverse)
 * Generates unique n-dimensional permutation matrices from the encryption key
 */
cs *gen_permut_mat(struct cipher *c, int dimension, boolean inverse) {
    int num_matrices = 1;
    if(2*dimension > 16) {
        num_matrices = (((2*dimension) - ((2*dimension)%16))/16) + 1;
    }
    char *linked = (char *)malloc(sizeof(char)*(16*dimension));
    memset(linked, '\0', strlen(linked));
    //create string used to choose permutation matrix
    for(int i = 0; i < num_matrices; i++) {
        int logBase = i + dimension;
        char *logBaseOutput = gen_log_base_str(c, logBase);
        sprintf(linked, "%s%s", linked, logBaseOutput);
        free(logBaseOutput);
    }
    //create linked lists used to build matrices
    i_head = (struct node *)malloc(sizeof(struct node));
    i_head->last = NULL;
    i_head->number = 0;
    //{.next = NULL, .last = NULL, .number = 0};
    i_head->next = next_node(i_head, dimension);
    j_head = (struct node *)malloc(sizeof(struct node));
    //{.next = NULL, .last = NULL, .number = 0};
    j_head->last = NULL;
    j_head->number = 0;
    j_head->next = next_node(j_head, dimension);
    int list_len = dimension;
    //create permutation matrix
    double ast[dimension];
    int ist[dimension];
    int jst[dimension];
    int dimension_counter = 0;
    for(int k = 0; k < 2*dimension; k+=2) {
        ast[dimension_counter] = 1.0;
        if(list_len == 1) {
            ist[dimension_counter] = i_head->number;
            jst[dimension_counter] = j_head->number;
        } else {
            int row = charAt(linked, k) - '0';
            row = row % list_len;
            printf("row: %d\n", row);
            int i_val = pull_node(true, row);
            ist[dimension_counter] = i_val;
            int column = charAt(linked, k+1) - '0';
            column = column % list_len;
            printf("column: %d\n", column);
            int j_val = pull_node(false, column);
            jst[dimension_counter] = j_val;
            dimension_counter++;
            list_len--;
        }
    }
    free(linked);
    //put permutation matrix in cipher dictionary
    remove("stdio_temp.st");
    r8st_write("stdio_temp.st", dimension, dimension, dimension, ist, jst, ast);
    FILE *f_mat = fopen("stdio_temp.st", "r");
    cs *load_triplet = cs_load(f_mat);
    fclose(f_mat);
    remove("stdio_temp.st");
    cs *permut_matrix = cs_triplet(load_triplet);
    return inverse ? cs_transpose(permut_matrix, dimension) : permut_matrix;
}

char charAt(char *ch, int index) {
    char *ptr = ch;
    ptr = ptr + index;
    return *ptr;
}

/*
 * Recursively creates new nodes until the correct length has been reached
 */
struct node *next_node(struct node *last, int dimension) {
    struct node *next = (struct node *)malloc(sizeof(struct node));
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
    struct node *cur = row ? i_head : j_head;
    for(int i = count; i > 1; i--) {
        cur = cur->next;
    }
    int num = cur->number;
    if(cur->last == NULL && cur->next != NULL) { //first node in list
        if(row) {
            i_head = i_head->next;
            i_head->last = NULL;
        } else {
            j_head = j_head->next;
            j_head->last = NULL;
        }
    } else if(cur->next == NULL && cur->last != NULL) { //last node in list
        cur->last->next = NULL;
    } else { //middle node in list
        cur->last->next = cur->next;
        cur->next->last = cur->last;
    }
    //todo free node
    //free(cur);
    //free_node(cur);
    return num;
}

//*
// * Frees a node's resources
// */
//void free_node(struct node *cur) {
//    free(cur->next);
//    free(cur->last);
//    free(cur);
//}

/*
 * Takes the matrix dimension, a list of bytes from the file and relevant permutation matrix
 * Performs the linear transformation operation on the byte vector and returns the resulting vector
 */
cs *transform_vec(int dimension, char bytes[], cs *permutation_mat) {
    int *ist = (int *)malloc(sizeof(int)*dimension);
    int *jst = (int *)malloc(sizeof(int)*dimension);
    double *ast = (double *)malloc(sizeof(double)*dimension);
    for(int i = 0; i < dimension; i++) {
        ist[i] = i;
        jst[i] = 0;
        ast[i] = bytes[i];
    }
    r8st_write("stdio_vec_temp.st", dimension, dimension, dimension, ist, jst, ast);
    FILE *f_in = fopen("stdio_vec_temp.st", "r");
    cs *load_triplet = cs_load(f_in);
    fclose(f_in);
    remove("stdio_vec_temp.st");
    cs *data_vec = cs_triplet(load_triplet);
    cs *result = cs_multiply(permutation_mat, data_vec);
    cs_print(result, 0);
    double *ptr = result->x;
    while(*ptr != '\0') {
        printf("%lf\n", *ptr);
        ptr++;
    }
    printf("-----------\n");
    free(ist);
    free(jst);
    free(ast);
    return result;
}

void distributor(struct cipher *c, FILE *in, FILE *out, int coeff) {
    char *encrypt_map = gen_log_base_str(c, exp(1));
    //create encrypt map of length required for file instead of looping
    int map_len = (int)strlen(encrypt_map);
    for(int map_itr = 0; c->bytes_remainging > 1024; map_itr++) {
        if(map_itr == map_len) {
            map_itr = 0;
        }
        int dimension = charAt(encrypt_map, map_itr) - '0';
        permut_cipher(c, in, out, coeff*dimension);
    }
    int b = (int) c->bytes_remainging;
    if(b > 0) {
        permut_cipher(c, in, out, coeff*b);
    }
    free(encrypt_map);
}

void permut_cipher(struct cipher *c, FILE *in, FILE *out, int dimension) {
    cs *pm = lookup(c, dimension);
    boolean inverse = dimension < 0;
    dimension = abs(dimension);
    cs *permutation_mat = pm ? pm : gen_permut_mat(c, dimension, inverse);
    char *data_in = (char *)malloc(sizeof(char)*dimension);
    fread(data_in, 1, (size_t)dimension, in);
    cs *result = transform_vec(dimension, data_in, permutation_mat);
    //parse result, done w/ coefficient value
    unsigned char *byte_data = (unsigned char *) malloc(sizeof(unsigned char) * dimension);
    memset(byte_data, '\0', sizeof(char)*dimension);
    int *byte_ptr = result->i;
    //optimize double --> int --> unsigned char
    for(int i = 0; i < dimension; i++) {
        int val_indx = *byte_ptr;
        //printf("%d\n", val_indx);
        byte_data[val_indx] = (unsigned char)*(result->x+i);
        printf("%d\n", byte_data[val_indx]);
        byte_ptr++;
    }
    for(int j = 0; j < dimension; j++) {
        printf("%d\n", byte_data[j]);
    }
    fwrite(byte_data, 1, (size_t)dimension, out);
    free(data_in);
    free(byte_data);
    c->bytes_remainging -= dimension;
}

//int run_cypher(struct cipher *c, char *file_name, )
void hello(struct cipher *c) {
    st_test();
    FILE *f = fopen("a2by2_r8.st", "r");
    cs *M = cs_load(f);
    cs *T = cs_triplet(M);
    c->permut_map[2] = T;
    cs *mat = lookup(c, size);
    if(mat != NULL) {
        cs_print(mat, 0);
    } else {
        printf("matrix size %d does not exist\n", size);
    }

}

cs *lookup(struct cipher *c, int size) {
    return size < 0 ? c->inv_permut_map[abs(size)] : c->permut_map[abs(size)];
}

void st_test()
{
    double ast[4] = {
            1.0, 2.0, 3.0, 4.0 };
    int i_max;
    int i_min;
    int ist[4] = {
            0, 0, 1, 1};
    int j_max;
    int j_min;
    int jst[4] = {
            0, 1, 0, 1};
    int n = 2;
    // number non-zero elements
    int nst = 4;
    int m = 2;
    char output_filename[] = "a2by2_r8.st";

    printf ( "\n" );
    printf ( "R8ST_WRITE\n" );
    printf ( "  R8ST_WRITE writes an R8ST file.\n" );

    //decrement for zero-based matrix
    //i4vec_dec ( nst, ist );
    //i4vec_dec ( nst, jst );

    i_min = i4vec_min ( nst, ist );
    i_max = i4vec_max ( nst, ist );
    j_min = i4vec_min ( nst, jst );
    j_max = i4vec_max ( nst, jst );

    r8st_header_print ( i_min, i_max, j_min, j_max, m, n, nst );

    r8st_print ( m, n, nst, ist, jst, ast,
                 "  Sparse Triplet (ST) data:" );

    r8st_write ( output_filename, m, n, nst, ist, jst, ast );

    printf ( "\n" );
    printf ( "  Wrote the matrix data to '%s'\n", output_filename );
}



