/*
 * util.h
 * Copyrite (c) Kyle Won, 2021
 * FontBlanc_C utilies header file.
 */

#ifndef FONT_BLANC_C_UTIL_H
#define FONT_BLANC_C_UTIL_H

#define LOG_OUTPUT "fontblanc_log.txt"
#define BUFFER 256
#define MAX_THREADS 8
typedef enum { false, true } boolean;

/*
 * Contains global information from initial arguments. Can include first instruction.
 */
typedef struct initial_state {
  int encrypt;
  // Permuation matrix dimmension, 0 if variable
  int dimension;
  boolean delete_when_done;
  // Specifies whether to perform data integrity check after every linear transformation
  boolean integrity_check;
  // Specifies whether to enter instruction input loop for multiple passes
  boolean multilevel;
  char *encrypt_key;
  char *output_path;
} initial_state;

/*
 * Contains information from user input for one instruction (one pass of encryption/decryption).
 */
typedef struct command {
  // Permuation matrix dimmension, 0 if variable
  int dimension;
  char *encrypt_key;
  // Specifies whether to perform data integrity check after every linear transformation
  boolean integrity_check;
  // Specifies whether to remove last instruction
  boolean remove_last;
  boolean help;
} command;

// Main function helpers ---------------------------------------------------------------------------
void get_key(char *);
void remove_newline(char *);
void fatal(char *, char *);

// Linked list -------------------------------------------------------------------------------------
typedef struct node {
  struct node *next;
  struct node *last;
  int number;
} node;

node **trash;
int trash_indx;

void init_ll_trash(int);
node *build_ll(node *, int);
int pull_node(node **, int);
void remove_node(node **, node *);
void empty_trash(void);
void free_ll_trash();

// FontBlanc_C helpers -----------------------------------------------------------------------------
char *get_extension(char *);
void remove_extension(char *, char *);
char **parse_f_path(char *);
long get_f_len(char *);
char charAt(char *, int);

#endif //FONT_BLANC_C_UTIL_H
