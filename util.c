/*
 * util.c
 * Copyrite (c) Kyle Won, 2021
 * Miscellaneous general purpose helper functions for FontBlanc_C main and core.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include "util.h"

// Main function helpers ---------------------------------------------------------------------------

/*
 * Uses termios to disable terminal echoing and reads encrypt key from user input.
 */
void get_key(char *encrypt_key) {
  printf("Enter key: ");
  struct termios term;
  tcgetattr(fileno(stdin), &term);
  term.c_lflag &= ~ECHO;
  tcsetattr(fileno(stdin), 0, &term);
  if(!fgets(encrypt_key, BUFFER, stdin)) {
    fatal(LOG_OUTPUT, "Error reading key input.");
  }
  term.c_lflag |= ECHO;
  tcsetattr(fileno(stdin), 0, &term);
}

/*
 * Removes newline character, if it exists, from the end of the given string.
 */
void remove_newline(char *s) {
  size_t s_len = strlen(s);
  if(*(s + (s_len - 1)) == '\n') {
    *(s + (s_len - 1)) = '\0';
  }
}

/*
 * Prints error message to given log file and exits program.
 */
void fatal(char *log_path, char *message) {
  time_t curtime = time(NULL);
  struct tm *loctime = localtime(&curtime);
  char out[BUFFER];
  snprintf(out, BUFFER, "\n%s%s\n", asctime(loctime), message);
  FILE* log = fopen(log_path, "a");
  printf("\nFontBlanc - ERROR: %s\n", out);
  fwrite(out, sizeof(char), strlen(out), log);
  fclose(log);
  exit(-1);
}

// Linked List -------------------------------------------------------------------------------------

/*
 * Allocates the trash to be 2 time given size of linked list to accommodate
 * for the two "row" and "column" lists.
 */
void init_ll_trash(int ll_size) {
  node **t = (node **)malloc(sizeof(node *) * (ll_size * 2));
  if(!t) {
    fatal(LOG_OUTPUT, "Dynamic memory allocation error in init_ll_trash, util.c."); exit(-1);
  }
  trash = t;
}

/*
 * Recursively creates new nodes until the correct length has been reached.
 */
node *build_ll(node *last, int dimension) {
  node *cur = (node *)malloc(sizeof(*cur));
  cur->last = last;
  cur->number = last->number + 1;
  if(cur->number == dimension - 1) {
    cur->next = NULL;
  } else {
    cur->next = build_ll(cur, dimension);
  }
  return cur;
}

/*
 * Fetches a node from the given linked list and deletes node from the list.
 * Takes whether the list is the row or column list and the node index.
 * Returns the number corresponding to the node in question.
 */
int pull_node(node **head, int count) {
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
  trash[trash_indx] = cur;
  trash_indx++;
  return num;
}

/*
 * Removes the given node from the linked list of the given head node.
 */
void remove_node(node **head, node *n) {
  if(!n) {
    return;
  }
  if(!n->last && n->next) { //first node in list
    *head = (*head)->next;
    (*head)->last = NULL;
  } else if(!n->next && n->last) { //last node in list
    n->last->next = NULL;
  } else if(n->next && n->last){ //middle node in list
    n->last->next = n->next;
    n->next->last = n->last;
  } // Else, last node in list
}

/*
 * Frees linked list nodes in trash array.
 */
void empty_trash() {
  for(int i = 0; i < trash_indx; i++) {
    if(trash[i]) {
      free(trash[i]);
      trash[i] = NULL;
    }
  }
}

/*
 * Frees trash array. Make sure to call empty_trash() first.
 */
void free_ll_trash() {
  free(trash);
}

// FontBlanc_C helpers -----------------------------------------------------------------------------

/*
 * Returns the extension of a given file name.
 */
char *get_extension(char *file_name) {
  size_t name_len = strlen(file_name);
  char *ptr = file_name + name_len;
  size_t ext_len;
  for(ext_len = 0; *(ptr-1) != '.' && ext_len < name_len; ext_len++) {
    ptr--;
  }
  return (ptr - 1);
}

/*
 * Removes given extension from given file name.
 * Pre-condition: file_name must end with the given extension.
 */
void remove_extension(char *file_name, char *extension) {
  size_t extension_len = strlen(extension);
  size_t filename_len = strlen(file_name);
  *(file_name + (filename_len - extension_len)) = '\0';
}

/*
 * Separates the file path from the file name.
 * Returns file name and file path up to the name.
 */
char **parse_f_path(char *file_path) {
  size_t path_len = strlen(file_path);
  char *ptr = file_path + path_len;
  size_t name_len;
  for(name_len = 0; *(ptr-1) != '/' && name_len < path_len; name_len++) {
    ptr--;
  }
  //allocate double pointer to store returned file vals
  char **processed = (char **)malloc(sizeof(char *)*2);
  processed[0] = (char *)calloc(BUFFER, sizeof(char));
  processed[1] = (char *)calloc(BUFFER, sizeof(char));
  strncpy(processed[0], ptr, (size_t)name_len);
  size_t keep = path_len - name_len;
  strncpy(processed[1], file_path, keep);
  return processed;
}

/*
 * Returns the size in bytes of the file at the given path.
 */
long get_f_len(char *file_path) {
  FILE *f;
  if(access(file_path, F_OK) != -1) {
    f = fopen(file_path, "r");
    fseek(f, 0, SEEK_END);
    long file_len = ftell(f);
    //printf("File length: %ld\n", file_len);
    fseek(f, 0, SEEK_SET);
    fclose(f);
    return file_len;
  } else {
    return -1;
  }
}

/*
 * Returns the character at the given index of a given char array.
 */
char charAt(char *ch, int index) {
  char *ptr = ch;
  ptr = ptr + index;
  return *ptr;
}
