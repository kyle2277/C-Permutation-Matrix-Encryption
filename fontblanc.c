/*
 * fontblanc.c
 * Copyrite (c) Kyle Won, 2021
 * FontBlanc_C core.
 */

#include "fontblanc.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <semaphore.h>
#include <pthread.h>
#include "fontblanc.h"
#include "Dependencies/st_to_cc.h"
#include "Dependencies/csparse.h"

clock_t time_total_gen;
clock_t time_total_write;
clock_t time_transformation;
clock_t time_p_loop;


// Synchronization variables for multithreading ----------------------------------------------------

// Controls max number of threads creatable at once
sem_t *thread_sema;
// Lock for condition variable
pthread_mutex_t *cipher_lock;
// Condition variable which signals when main thread can terminate
pthread_cond_t *condvar;
// Lock for generating permutation matrices
pthread_mutex_t *permut_lock;
// -------------------------------------------------------------------------------------------------

// Globals for multithreaded generation of permutation matrices ------------------------------------

// For fixed dimension: contains dimensions of all permutation matrices to be created
// For variable dimension: bitmap of which dimensions need to be generated
int *dim_array;
// Size of array storing matrices to be generated
_Atomic int dim_array_size;
// Number of matrices to be generated
int num_array;
// Index counter keeps track of which matrices have been assigned to threads
int dim_index;
// Counter keeps track of how many matrices are finished
_Atomic int dim_finished;

// -------------------------------------------------------------------------------------------------

// Globals for multithreaded linear transformations ------------------------------------------------

// Number of threads created
int scheduled_chunks;
// Number of threads finished
_Atomic int finished_chunks;

// Information for performing fixed sized linear transformations on a chunk of a file
typedef struct fixed_transform_thread {
  cipher *ciph;
  // Starting point in file
  long offset;
  // Number of bytes to process
  long length;
  // Permutation matrix dimension
  int dimension;
  // Indicates matrix inverse
  int coeff;
} fixed_transform_thread;

// Information for performing variable sized linear tranformations on a chunk of a file
typedef struct variable_transform_thread {
  cipher *ciph;
  // Starting point in file
  long offset;
  // Number of bytes to process
  long length;
  // String of values for generating dimensions
  char *dimension_vals;
  // Index of first dimension value in dimension_vals
  int map_itr_start;
  // Indicates matrix inverse
  int coeff;
  // Indicates if last thread should run to eof
  boolean last;
} variable_transform_thread;
// -------------------------------------------------------------------------------------------------

// Constructors and Destructors

/*
 * Create a cipher structure for the given file with the given encryption key.
 * Returns the cipher structure.
 */
cipher *create_cipher(char *file_name, char *file_path, long file_len, char *output_name) {
  cipher *c = malloc(sizeof(cipher));
  if(!c) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in create_cipher(), fontblanc.c"); exit(-1);
  }
  c->log_path = LOG_OUTPUT;
  c->file_name = file_name;
  c->output_name = output_name;
  c->file_path = file_path;
  c->file_len = file_len;
  c->bytes_remaining = file_len;
  c->bytes_processed = 0;
  c->instructions = NULL;
  c->num_instructions = 0;
  c->integrity_check = true;
  // 9 variations of perumation matrices, mapped to base 10 digits 1-9
  c->permut_map = (struct PMAT **)calloc(11, sizeof(struct PMAT *));
  if(!c->permut_map) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in create_cipher(), fontblanc.c"); exit(-1);
  }
  thread_sema = (sem_t *)malloc(sizeof(sem_t));
  sem_init(thread_sema, 0, num_threads);
  cipher_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(cipher_lock, NULL);
  condvar = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
  pthread_cond_init(condvar, NULL);
  permut_lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(permut_lock, NULL);
  // DEBUG OUTPUT
  //debug = fopen("FB_WO_debug.txt", "a");
  return c;
}

/*
 * Frees given cipher object.
 */
int close_cipher(cipher *c) {
  //todo segfault when free file_name
  //free(c->file_path);
  //free(c->instructions);
  free(c->file_bytes);
  free(c->permut_map);
  free(c);
  sem_destroy(thread_sema);
  free(thread_sema);
  pthread_mutex_destroy(cipher_lock);
  free(cipher_lock);
  pthread_cond_destroy(condvar);
  free(condvar);
  pthread_mutex_destroy(permut_lock);
  free(permut_lock);
  return 1;
}

// Core operations ---------------------------------------------------------------------------------

/*
 * Run the process. Takes cipher and whether tp encrypt or not.
 */
int run(cipher *c, boolean encrypt) {
    int coeff = encrypt ? 1 : -1;
    time_total_gen = 0;
    time_total_write = 0;
    time_transformation = 0;
    time_p_loop = 0;
    unsigned char *file_bytes = read_input(c);
    c->file_bytes = file_bytes;
    read_instructions(c, coeff);
    write_output(c, coeff);
    if(verbose_lvl_2) {
      printf("Time generating permutation matrices (ms): %.2lf\n", (double)time_total_gen*1000/CLOCKS_PER_SEC);
      printf("Time writing matrices to file (ms): %.2lf\n", (double)time_total_write*1000/CLOCKS_PER_SEC);
      printf("Time performing linear transformation (ms): %.2lf\n", (double)time_transformation*1000/CLOCKS_PER_SEC);
      printf("Time in node pull loop (ms): %.2lf\n", (double)time_p_loop*1000/CLOCKS_PER_SEC);
    }
    return 1;
}

/*
 * Processes a section of a file using variable dimension permutation matrices.
 */
void *variable_thread_func(void *args) {
  //create encrypt map of length required for file instead of looping
  //todo limits file size to max size of unsigned int in bytes, ~4GB
  if(!args) {
    fatal(LOG_OUTPUT, "Null args reference in fixed_thread_func(), fontblanc.c."); exit(EXIT_FAILURE);
  }
  variable_transform_thread *vtt = (variable_transform_thread *)args;
  long bytes_remaining = vtt->length;
  long working_offset = vtt->offset;
  int limit = vtt->last ? MAX_DIMENSION : 0;
  if(bytes_remaining > limit) {
    int map_len = (int)strlen(vtt->dimension_vals);
    for(int map_itr = vtt->map_itr_start; bytes_remaining > limit; map_itr++) {
      int map_index = (charAt(vtt->dimension_vals, map_itr % map_len) - '0');
      map_index = map_index > 1 ? map_index : 1;
      int dimension = map_index > 1 ? MAX_DIMENSION - (MAX_DIMENSION / map_index) : MAX_DIMENSION;
      permut_cipher(vtt->ciph, map_index, working_offset);
      bytes_remaining -= dimension;
      working_offset += dimension;
    }
  }
  int dimension = (int) bytes_remaining;
  if(dimension > 0) {
    // Generate final permutation matrix of arbitrary size
    // Create last permutation matrix of arbitrary size on-demand
    permut_thread *pt = (permut_thread *)malloc(sizeof(permut_thread));
    pt->index = dim_index;
    pt->dimension = dimension;
    pt->c = vtt->ciph;
    pt->inverse = vtt->coeff < 0;
    pt->post = false;
    pthread_t thread;
    pthread_create(&thread, NULL, permut_thread_func, (void *) pt);
    pthread_join(thread, NULL);
    dim_array_size += 1;
    // Last matrix stored 11th array slot, index 10
    permut_cipher(vtt->ciph, 10, working_offset);
  }
  free(vtt);
  finished_chunks += 1;
  sem_post(thread_sema);
  pthread_cond_broadcast(condvar);
  pthread_detach(pthread_self());
  return NULL;
}

/*
 * Splits file into MAX_THREADS chunks each of which to be processed by a thread using variable
 * dimension transformations.
 */
void variable_thread_scheduler(cipher *c, int coeff) {
  finished_chunks = 0;
  scheduled_chunks = 0;
  int map_index = 0;
  long working_offset = 0;
  long bytes_remaining = c->file_len;
  long calculations_per_chunk = c->file_len / (MAX_DIMENSION) / num_threads;
  long approx = c->file_len / MAX_DIMENSION;
  char *linked = gen_linked_vals(c, (unsigned int)approx);
  int map_len = (int)strlen(linked);
  if(verbose_lvl_2) {
    printf("Performing linear transformations...\n");
  }
  if(calculations_per_chunk > 0) {
    for(int i = 0; i < (num_threads - 1); i++) {
      if(bytes_remaining < MAX_DIMENSION) {
        break;
      }
      int length = 0;
      int map_itr_start = map_index % map_len;
      for(int j = 0; j < calculations_per_chunk; j++, map_index++) {
        int tmp = (charAt(linked, map_index % map_len) - '0');
        int dimension = tmp > 1 ? MAX_DIMENSION - (MAX_DIMENSION / tmp) : MAX_DIMENSION;
        if((bytes_remaining - dimension) < 0) {
          break;
        }
        length += dimension;
        bytes_remaining -= dimension;
      }
      // Acquire available thread
      sem_wait(thread_sema);
      pthread_t thread;
      variable_transform_thread *vtt = (variable_transform_thread *)malloc(sizeof(variable_transform_thread));
      if(!vtt) {
        fatal(LOG_OUTPUT, "Dynamic memory allocation error in fixed_thread_scheduler(), fontblanc.c.");
        exit(EXIT_FAILURE);
      }
      vtt->map_itr_start = map_itr_start;
      vtt->length = length;
      vtt->offset = working_offset;
      vtt->dimension_vals = linked;
      vtt->coeff = coeff;
      vtt->ciph = c;
      vtt->last = false;
      working_offset += length;
      scheduled_chunks += 1;
      pthread_create(&thread, NULL, variable_thread_func, (void *)vtt);
    }
  }

  // Acquire available thread
  sem_wait(thread_sema);
  pthread_t thread;
  variable_transform_thread *vtt = (variable_transform_thread *)malloc(sizeof(variable_transform_thread));
  if(!vtt) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in fixed_thread_scheduler(), fontblanc.c.");
    exit(EXIT_FAILURE);
  }
  vtt->map_itr_start = map_index % map_len;
  vtt->offset = working_offset;
  vtt->length = c->file_len - working_offset;
  vtt->dimension_vals = linked;
  vtt->coeff = coeff;
  vtt->ciph = c;
  vtt->last = true;
  scheduled_chunks += 1;
  pthread_create(&thread, NULL, variable_thread_func, (void *)vtt);
  // Wait for all threads to finish
  pthread_mutex_lock(cipher_lock);
  while(finished_chunks < scheduled_chunks) {
    pthread_cond_wait(condvar, cipher_lock);
  }
  free(linked);
  pthread_mutex_unlock(cipher_lock);
}

/*
 * Processes a section of a file using fixed dimension permutation matrix.
 */
void *fixed_thread_func(void *args) {
  if(!args) {
    fatal(LOG_OUTPUT, "Null args reference in fixed_thread_func(), fontblanc.c."); exit(EXIT_FAILURE);
  }
  fixed_transform_thread *ftt = (fixed_transform_thread *)args;
  long bytes_remaining = ftt->length;
  long working_offset = ftt->offset;
  while(bytes_remaining >= ftt->dimension) {
    // Permutation matrix of size dimension stored in permut_map index 1
    permut_cipher(ftt->ciph, 1, working_offset);
    bytes_remaining -= ftt->dimension;
    working_offset += ftt->dimension;
  }
  if(bytes_remaining > 0) {
    // Permutation matrix of size bytes_remaining stored in permut_map index 2
    permut_cipher(ftt->ciph, 2, working_offset);
  }
  free(ftt);
  finished_chunks += 1;
  sem_post(thread_sema);
  pthread_cond_broadcast(condvar);
  pthread_detach(pthread_self());
  return NULL;
}

/*
 * Splits file into MAX_THREADS chunks each of which to be processed by a thread using fixed
 * dimension tranformations.
 */
void fixed_thread_scheduler(cipher *c, int coeff, int dimension) {
  long chunk_size;
  int chunk_index;
  finished_chunks = 0;
  scheduled_chunks = 0;
  if(verbose_lvl_2) {
    printf("Performing linear transformations...\n");
  }
  if(c->file_len > dimension) {
    long calculations_per_chunk = c->file_len / dimension / num_threads;
    chunk_size = calculations_per_chunk * dimension;
    for(chunk_index = 0; chunk_index < (num_threads - 1); chunk_index++) {
      if((chunk_index * chunk_size) + chunk_size > c->file_len) {
        break;
      }
      // Acquire available thread
      sem_wait(thread_sema);
      pthread_t thread;
      fixed_transform_thread *ftt = (fixed_transform_thread *)malloc(sizeof(fixed_transform_thread));
      if(!ftt) {
        fatal(LOG_OUTPUT, "Dynamic memory allocation error in fixed_thread_scheduler(), fontblanc.c.");
        exit(EXIT_FAILURE);
      }
      ftt->dimension = dimension;
      ftt->offset = chunk_size * chunk_index;
      ftt->length = chunk_size;
      ftt->coeff = coeff;
      ftt->ciph = c;
      scheduled_chunks += 1;
      pthread_create(&thread, NULL, fixed_thread_func, (void *)ftt);
    }
  } else {
    chunk_size = c->file_len;
    chunk_index = 0;
  }
  // Schedule last thread
  sem_wait(thread_sema);
  pthread_t thread;
  fixed_transform_thread *ftt = (fixed_transform_thread *)malloc(sizeof(fixed_transform_thread));
  if(!ftt) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in fixed_thread_scheduler(), fontblanc.c.");
    exit(EXIT_FAILURE);
  }
  ftt->dimension = dimension;
  ftt->offset = chunk_size * chunk_index;
  // Last thread takes arbitrary chunk size to eof
  ftt->length = c->file_len - ftt->offset;
  ftt->coeff = coeff;
  ftt->ciph = c;
  scheduled_chunks += 1;
  pthread_create(&thread, NULL, fixed_thread_func, (void *)ftt);
  // Wait for all threads to finish
  pthread_mutex_lock(cipher_lock);
  while(finished_chunks < scheduled_chunks) {
    pthread_cond_wait(condvar, cipher_lock);
  }
  pthread_mutex_unlock(cipher_lock);
}

/*
 * Facilitates matrix transformations.
 */
void permut_cipher(cipher *c, int map_index, long ref) {
  unsigned char *data = c->file_bytes;
  struct PMAT *permutation_mat = c->permut_map[map_index];
  if(!permutation_mat) {
    fatal(LOG_OUTPUT, "Null reference to permutation matrix in permut_cipher(), fontblanc.c.");
    exit(EXIT_FAILURE);
  }
  int dimension = permutation_mat->dimension;
  unsigned char *data_in = (unsigned char *)calloc((size_t)dimension + 1, sizeof(unsigned char));
  memcpy(data_in, data+ref, (size_t)sizeof(unsigned char)*dimension);
  double *result = transform_vec(dimension, data_in, permutation_mat, c->integrity_check);
  //check for data preservation error
  if(result == NULL) {
    char message[BUFFER];
    snprintf(message, BUFFER, "%s\n%ld%s\n%s\n", "Corruption detected in encryption.", c->bytes_remaining,
             " unencrypted bytes remaining.", "Aborting.");
    fatal(c->log_path, message);
  }
  double *ptr = result;
  unsigned char *data_result = (unsigned char *)realloc(data_in, sizeof(unsigned char)*(dimension + 1));
  memset(data_result, '\0', (size_t)dimension + 1);
  for(int i = 0; i < dimension; i++, ptr++) {
    data_result[i] = (unsigned char)*ptr;
  }
  memcpy(data+ref, data_result, (size_t)dimension);
  free(data_result);
  free(result);
  c->bytes_processed += dimension;
  c->bytes_remaining -= dimension;
}

// Matrix operations -------------------------------------------------------------------------------

/*
 * Allocates space for a matrix object.
 */
struct PMAT *init_permut_mat(int dimension) {
  //initialize new matrix object
  struct PMAT_I *mi = (struct PMAT_I *)malloc(sizeof(struct PMAT_I) + sizeof(int)*(dimension));
  //size is N columns + 1 as required by cc_mv matrix multiplication
  struct PMAT_I *mj = (struct PMAT_I *)malloc(sizeof(struct PMAT_I) + sizeof(int)*(dimension + 1));
  struct PMAT_V *mv = (struct PMAT_V *)malloc(sizeof(struct PMAT_V) + sizeof(double)*(dimension));
  struct PMAT *m = (struct PMAT *)malloc(sizeof(struct PMAT));
  m->dimension = dimension;
  m->i = mi;
  m->j = mj;
  m->v = mv;
  m->check_vec_bef = (double *)calloc((size_t) dimension, sizeof(double));
  m->check_vec_aft = (double *)calloc((size_t) dimension, sizeof(double));
  return m;
}

/*
 * Fetches a node from the given linked list and deletes node from the list.
 * Takes whether the list is the row or column list and the node index.
 * Returns the number corresponding to the node in question.
 */
int pull_node(node **head, int count, permut_thread *pt) {
  node *cur = *head;
  for(int i = 0; i < count; ++i) {
    cur = cur->next;
  }
  if(!cur) {
    fatal(LOG_OUTPUT, "Linked list null pointer reference in remove_node, util.c."); exit(-1);
  }
  int num = cur->number;
  remove_node(head, cur);
  //free the node later
  pt->trash[pt->trash_index] = cur;
  pt->trash_index += 1;
  return num;
}

/*
 * Generates a permutation matrix on the current thread of the given dimension.
 */
void *permut_thread_func(void *args) {
  if(!args) {
    fatal(LOG_OUTPUT, "Null args reference in thread_func(), fontblanc.c."); exit(EXIT_FAILURE);
  }
  permut_thread *pt = (permut_thread *)args;
  pt->trash = init_ll_trash(pt->dimension);
  pt->trash_index = 0;
  gen_permut_mat(pt);
  empty_trash(pt->trash, pt->trash_index);
  free_ll_trash(pt->trash);
  dim_finished ++;
  pthread_cond_broadcast(condvar);
  if(verbose_lvl_2) {
    printf("Finished matrix: %d\n", pt->dimension);
  }
  if(pt->post) {
    // Make new thread available
    sem_post(thread_sema);
    pthread_detach(pthread_self());
  }
  free(pt);
  return NULL;
}

/*
 * Creates threads to generate permutation matrices for linear transformations of 9 variable sizes.
 */
void gen_variable_permut_mats(cipher *c, int coeff) {
  // 10 slots for perumation matrices, 9 mapped to base 10 digits 1-9 + one extra for last
  // matrix of arbitrary size
  dim_array = (int *)calloc(11, sizeof(int));
  if(!dim_array) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in gen_variable_permut_mats(), fontblanc.c.");
    exit(EXIT_FAILURE);
  }
  dim_array_size = 10;
  // 'finished' matrix in 0 index
  dim_finished = 1;
  dim_index = 1;
  for(int i = 1; i < 10; i++) {
    dim_array[i] = i > 1 ? MAX_DIMENSION - (MAX_DIMENSION / i) : MAX_DIMENSION;
  }
  if(verbose_lvl_2) {
    printf("Generating matrices...\n");
  }
  // Generate permutation matrices in parallel
  while(dim_index < dim_array_size) {
    // Wait until a thread is available
    sem_wait(thread_sema);
    permut_thread *pt = (permut_thread *)malloc(sizeof(permut_thread));
    pt->index = dim_index;
    pt->dimension = dim_array[dim_index];
    pt->c = c;
    pt->inverse = coeff < 0;
    pt->post = true;
    pthread_t thread;
    pthread_create(&thread, NULL, permut_thread_func, (void *) pt);
    dim_index += 1;
  }
  pthread_mutex_lock(cipher_lock);
  while(dim_finished < dim_array_size) {
    pthread_cond_wait(condvar, cipher_lock);
  }
  pthread_mutex_unlock(cipher_lock);
  free(dim_array);
}

/*
 * Creates threads to generate permutation matrices for linear transformations of size of the given dimension.
 */
void gen_fixed_permut_mats(cipher *c, int coeff, int dimension) {
  // Fixed dimension stored in 1st index, last dimension stored in 2nd index, nothing in 0th
  int last_dim = (int)((c->file_len) % dimension);
  dim_array_size = last_dim > 0 ? 3 : 2;
  dim_array = (int *)calloc((size_t)dim_array_size, sizeof(int));
  if(!dim_array) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in gen_fixed_permut_mats(), fontblanc.c.");
    exit(EXIT_FAILURE);
  }
  dim_array[1] = dimension;
  dim_array[2] = last_dim;
  dim_finished = 1;
  dim_index = 1;
  if(verbose_lvl_2) {
    printf("Generating matrices...\n");
  }
  // Generate permutation matrices in parallel
  while(dim_index < dim_array_size) {
    // Wait until a thread is available
    sem_wait(thread_sema);
    permut_thread *pt = (permut_thread *)malloc(sizeof(permut_thread));
    pt->index = dim_index;
    pt->dimension = dim_array[dim_index];
    pt->c = c;
    pt->inverse = coeff < 0;
    pt->post = true;
    pthread_t thread;
    pthread_create(&thread, NULL, permut_thread_func, (void *) pt);
    dim_index += 1;
  }
  pthread_mutex_lock(cipher_lock);
  while(dim_finished < dim_array_size) {
    pthread_cond_wait(condvar, cipher_lock);
  }
  pthread_mutex_unlock(cipher_lock);
  free(dim_array);
}

/*
 * Takes the dimension of the matrix to create (dimension is negative if inverse).
 * Generates unique n-dimensional permutation matrices from the encryption key.
 */
void gen_permut_mat(permut_thread *pt) {
  clock_t start = clock();
  cipher *c = pt->c;
  int dimension = pt->dimension;
  boolean inverse = pt->inverse;
  if(verbose_lvl_2) {
    printf("%s%d\n", "Generating matrix: ", dimension);
  }
  char *linked = gen_linked_vals(c, 2*dimension);
  //create linked lists used to build matrices
  node *i_head = (node *)malloc(sizeof(node));
  i_head->last = NULL;
  i_head->number = 0;
  i_head->next = build_ll(i_head, dimension);
  node *j_head = (node *)malloc(sizeof(node));
  j_head->last = NULL;
  j_head->number = 0;
  j_head->next = build_ll(j_head, dimension);
  //create permutation matrix
  double acc[dimension];
  int icc[dimension];
  int jcc[dimension+1];
  struct PMAT *m = init_permut_mat(dimension);
  int dimension_counter = 0;
  int list_len = dimension;
  clock_t p_loop = clock();
  int i_val;
  int j_val;
  for(int k = 0; k < 2*dimension; k+=2) {
    acc[dimension_counter] = 1.0;
    if(list_len == 1) {
      i_val = pull_node(&i_head, 0, pt);
      j_val = pull_node(&j_head, 0, pt);
    } else {
      int row = (charAt(linked, k)-'0');
      row = ((row+1) * dimension) % list_len;
      i_val = pull_node(&i_head, row, pt);
      int column = (charAt(linked, k+1)-'0');
      column = ((column+1) * dimension) % list_len;
      j_val = pull_node(&j_head, column, pt);
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
  free(linked);
  clock_t p_loop_diff = clock() - p_loop;
  time_p_loop += p_loop_diff;
  clock_t difference = clock() - start;
  time_total_gen += difference;
  //put permutation matrix in cipher dictionary
  clock_t start_write = clock();
  memcpy(m->i->icc, icc, sizeof(int)*dimension);
  memcpy(m->j->icc, jcc, sizeof(int)*(dimension+1));
  memcpy(m->v->acc, acc, sizeof(double)*dimension);
  struct PMAT *resultant_m;
  if(inverse) {
    resultant_m = orthogonal_transpose(m);
  } else {
    resultant_m = m;
  }
  c->permut_map[pt->index] = resultant_m;
  //create vector to check integrity of data
  if(c->integrity_check) {
    double *check_vec = cc_mv(dimension, dimension, dimension, resultant_m->i->icc, resultant_m->j->icc,
                              resultant_m->v->acc, resultant_m->check_vec_bef);
    memcpy(resultant_m->check_vec_aft, check_vec, sizeof(double)*dimension);
    free(check_vec);
  }
  clock_t diff_write = clock() - start_write;
  time_total_write += diff_write;
  //printf("created mat, %d\n", dimension);
  //return resultant_m;
}

/*
 * Takes the matrix dimension, a list of bytes from the file and relevant permutation matrix.
 * Performs the linear transformation operation on the byte vector and returns the resulting vector.
 */
double *transform_vec(int dimension, unsigned char bytes[], struct PMAT *pm, boolean integrity_check) {
  double vec[dimension];
  for(int i = 0; i < dimension; i++) {
    vec[i] = bytes[i];
  }
  clock_t transform_start = clock();
  // Data integrity check
  double *result = cc_mv(dimension, dimension, dimension, pm->i->icc, pm->j->icc, pm->v->acc, vec);
  if(integrity_check) {
    int dot_bef = dot_product(vec, pm->check_vec_bef, dimension);
    clock_t transform_diff = clock() - transform_start;
    time_transformation += transform_diff;
    int dot_aft = dot_product(result, pm->check_vec_aft, dimension);
    return dot_bef == dot_aft ? result : NULL;
  }
  clock_t transform_diff = clock() - transform_start;
  time_transformation += transform_diff;
  return result;
}

/*
 * Takes an orthogonal matrix object and transposes it (equal to the matrix inverse).
 * Returns the resulting matrix object.
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
  purge_mat(mat);
  return t_m;
}

/*
 * Takes two column vectors and their dimension.
 * Returns the dot product.
 */
int dot_product(double a[], double b[], int dimension) {
  double result = 0;
  for(int i = 0; i < dimension; i++) {
    result += a[i] * b[i];
  }
  return (int) result;
}

/*
 * zeroes out permutation matrix maps.
 */
void purge_maps(cipher *c) {
  for(int i = 1; i < dim_array_size; i++) {
    struct PMAT *pm = c->permut_map[i];
    if(pm) {
      purge_mat(pm);
      c->permut_map[i] = NULL;
    }
  }
}

/*
 * Zeroes out contents of matrix.
 */
void purge_mat(struct PMAT *pm) {
  memset(pm->i->icc, '\0', pm->dimension * sizeof(int));
  memset(pm->j->icc, '\0', (pm->dimension + 1) * sizeof(int));
  memset(pm->v->acc, '\0', pm->dimension * sizeof(double));
  memset(pm->check_vec_bef, '\0', pm->dimension * sizeof(double));
  memset(pm->check_vec_aft, '\0', pm->dimension * sizeof(double));
  pm->dimension = 0;
  free(pm->i);
  free(pm->j);
  free(pm->v);
  free(pm->check_vec_bef);
  free(pm->check_vec_aft);
  free(pm);
}

// Utilites ----------------------------------------------------------------------------------------

/*
 * Returns a pseudo-random number from the string input.
 */
int key_sum(char *s) {
  int sum = 0;
  for(int i = 0; *(s+1) != '\0'; s++, i++) {
    //subtract letter from the next and multiply by 2^i
    int add = (*s+*(s+1))<<i;
    sum = add-sum;
  }
  if(verbose_lvl_2) {
    printf("Key sum: %d\n", sum);
  }
  // DEBUG OUTPUT
//    char *debug_out = (char *)malloc(sizeof(char)*256);
//    sprintf(debug_out, "%d\n", sum);
//    fwrite(debug_out, sizeof(char), strlen(debug_out), debug);
  return sum;
}

/*
 * Takes cipher object and whether encrypt or decrypt.
 * Reads entire file into the program.
 */
unsigned char* read_input(cipher *c) {
  long file_len = c->file_len;
  FILE *in;
  char *f_in_path = (char *)malloc(sizeof(char) * BUFFER);
  sprintf(f_in_path, "%s%s", c->file_path, c->file_name);
  in = fopen(f_in_path, "r");
  unsigned char *file_bytes = (unsigned char *)calloc((size_t)file_len + 1, sizeof(unsigned char));
  fread(file_bytes, sizeof(unsigned char), (size_t)file_len, in);
  free(f_in_path);
  fclose(in);
  return file_bytes;
}

/*
 * Writes encrypted/decrypted data to file.
 */
void write_output(cipher *c, int coeff) {
  char *f_out_path = (char *)malloc(sizeof(char) * BUFFER);
  char *extension = get_extension(c->file_name);
  char *output_name = strlen(c->output_name) > 0 ? c->output_name : c->file_name;
  if(coeff > 0) { //encrypt
    // Only add extension to output if it doesn't already exist
    if(strcmp(extension, ENCRYPT_EXT) == 0) {
      sprintf(f_out_path, "%s%s", c->file_path, c->file_name);
    } else {
      sprintf(f_out_path, "%s%s%s", c->file_path, output_name, ENCRYPT_EXT);
    }
  } else { //decrypt
    // Check if need to remove extension
    if(strcmp(extension, ENCRYPT_EXT) == 0) {
      // remove extension
      remove_extension(c->file_name, ENCRYPT_EXT);
    }
    sprintf(f_out_path, "%s%s%s", c->file_path, DECRYPT_TAG, output_name);
  }
  FILE *out = fopen(f_out_path, "w");
  long file_len = c->file_len;
  fwrite(c->file_bytes, sizeof(unsigned char), (size_t)file_len, out);
  free(f_out_path);
  fclose(out);
  // DEBUG OUTPUT
  //fclose(debug);
}

/*
 * Generates a string of pseudo-random values of length provided.
 */
char *gen_linked_vals(cipher *c, int length) {
  int sequences = 1;
  if(length > 15) {
    sequences = ((length - (length % 15)) / 15) + 1;
  }
  //16 is the number of values in the log string
  char *linked = (char *)calloc((size_t)16 * sequences, sizeof(char));
  //create string used to choose permutation matrix
  for(int i = 2; i <= sequences + 1; i++) {
    //i + dimension = log base
    char *logBaseOutput = gen_log_base_str(c, (i + length));
    strncat(linked, logBaseOutput, strlen(logBaseOutput));
    free(logBaseOutput);
  }
  return linked;
}

/*
 * Generates unique, pseudo-random string of numbers using the encryption key.
 */
char *gen_log_base_str(cipher *c, double log_base) {
  double output = log(c->encrypt_key_val) / log(log_base);
  char *log_base_str = (char *)malloc(sizeof(char) * 32);
  sprintf(log_base_str, "%.16lf", output);
  //gets rid of everything before the decimal
  char *ch = log_base_str;
  while(*ch != '.') {
      ch++;
  }
  ch++;
  char *final_output = (char *)calloc(32, sizeof(char));
  strncpy(final_output, ch, (size_t)15);
  // DEBUG OUTPUT
//    char *write_debug = (char *)malloc(sizeof(char)*32);
//    sprintf(write_debug, "%s\n", final_output);
//    fwrite(write_debug, sizeof(char), strlen(write_debug), debug);
  free(log_base_str);
  return final_output;
}

// Instructions ------------------------------------------------------------------------------------

/*
 * Create an instruction to add to the cipher instructions array. Takes whether the array dimensions
 * should be fixed (0 = variable dimensions, >=1 = fixed dimension) and the dimension (if fixed)
 * Returns an array of instructions.
 */
instruction *create_instruction(int dimension, char *encrypt_key, boolean integrity_check) {
  instruction *i = (instruction *)malloc(sizeof(instruction));
  i->encrypt_key = (char *)calloc(BUFFER, sizeof(char));
  i->dimension = dimension;
  memcpy(i->encrypt_key, encrypt_key, sizeof(char)*(strlen(encrypt_key) + 1));
  i->integrity_check = integrity_check;
  return i;
}

/*
 * Sets instructions in given cipher. Must call before calling run().
 */
void set_instructions(cipher *c, instruction **instructions, int num_instructions) {
  c->instructions = instructions;
  c->num_instructions = num_instructions;
}

/*
 * Iterates through the instructions of the given cipher.
 */
void read_instructions(cipher *c, int coeff) {
  int num_instructions = c->num_instructions;
  if(num_instructions == 0) {
    fatal(LOG_OUTPUT, "No instructions found.");
  }
  int a;
  int b;
  if(coeff > 0) { //encrypt, read instructions forwards
    a = 0;
    b = num_instructions;
  } else { //coeff < 0, decrypt, read instructions backwards
    // todo num_instructions & b=0
    a = -1 * (num_instructions-1);
    b = 1;
  }
  //iterate through instructions
  int pass_index = 1;
  for(int i = a; i < b; i++, pass_index++) {
    instruction *cur = c->instructions[abs(i)];
    c->bytes_remaining = c->file_len;
    c->bytes_processed = 0;
    c->integrity_check = cur->integrity_check;
    //FIXED: dimension cannot be larger than max dimension
    int dimension = cur->dimension > MAX_DIMENSION ? MAX_DIMENSION : cur->dimension;
    size_t key_len = strlen(cur->encrypt_key);
    memcpy(c->encrypt_key, cur->encrypt_key, sizeof(char) * key_len + 1);
    //memset(cur->encrypt_key, '\0', sizeof(char)*key_len);
    c->encrypt_key_val = key_sum(c->encrypt_key);
    printf("Executing instruction %d...\n", pass_index);
    if(dimension > 0) { //fixed dimension
      // Generate matrices
      gen_fixed_permut_mats(c, coeff, dimension);
      // Perform linear transformations
      fixed_thread_scheduler(c, coeff, dimension);
    } else { //flexible dimension
      // Generate matrices
      gen_variable_permut_mats(c, coeff);
      // Perform linear transformations
      variable_thread_scheduler(c, coeff);
    }
    // todo move outside of instruction for loop?
    purge_maps(c);
    memset(c->encrypt_key, '\0', sizeof(char)*key_len);
    c->encrypt_key_val = 0;
  }
}

/*
 * Prints a single instruction at the given index. Does not notify if instruction at index exists.
 */
void print_instruction_at(instruction **instructions, int index) {
  // Convert from element number to index number
  if(index < 0) {
    return;
  }
  instruction *ins = instructions[index];
  if(!ins) {
    return;
  }
  printf("| Instruction #%d |\n", index + 1);
  printf("Key: %s\n", ins->encrypt_key);
  printf("Matrix dimension: ");
  if(ins->dimension > 0) {
    printf("%d\n", ins->dimension);
  } else {
    printf("variable\n");
  }
  printf("Data integrity checks: %s\n", ins->integrity_check ? "on" : "off");
  printf("\n");
}

/*
 * Prints specified number of instructions to stdout starting from first instruction.
 */
void print_instructions(instruction **instructions, int num_instructions) {
  if(num_instructions <= 0) {
    printf("No instructions added\n");
    return;
  }
  for(int i = 0; i < num_instructions; i++) {
    print_instruction_at(instructions, i);
  }
}

/*
 * Wrapper for print_instruction_at that prints the last instruction.
 */
void print_last_instruction(instruction **instructions, int num_instructions) {
  print_instruction_at(instructions, num_instructions - 1);
}

/*
 * Removes the last instruction. Returns new number of instructions.
 */
int remove_last_instruction(instruction **instructions, int num_instructions) {
  if(num_instructions <= 0) {
    // Cannot remove last instruction
    printf("No previous instruction to remove\n");
    return num_instructions;
  }
  // Remove last instruction
  instruction *remove = instructions[num_instructions - 1];
  memset(remove->encrypt_key, '\0', strlen(remove->encrypt_key));
  free(remove);
  printf("Removed instruction #%d\n", num_instructions);
  printf("\n");
  return num_instructions - 1;

}

/*
 * Zero's out encrypt key field in every instruction.
 */
void clean_instructions(instruction **instructions, int num_instructions) {
  for(int i = 0; i < num_instructions; i++) {
    instruction *cur = instructions[i];
    memset(cur->encrypt_key, '\0', strlen(cur->encrypt_key));
  }
}

/*
 * Frees dynamically allocated instruction memory.
 */
void free_instructions(instruction **instructions, int num_instructions) {
  for(int i = 0; i < num_instructions; i++) {
    free(instructions[i]->encrypt_key);
    free(instructions[i]);
  }
  free(instructions);
}