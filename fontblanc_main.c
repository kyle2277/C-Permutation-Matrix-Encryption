//
// Created by kylej on 6/15/21.
//

#include <stdio.h>
#include <stdlib.h>
#include "fontblanc.h"
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "Dependencies/csparse.h"
#include <getopt.h>
#include <termios.h>

#define OPTIONS "iedD:k:o:xmsh"

typedef struct user_command {
  int encrypt;
  int dimension;
  boolean delete_when_done;
  boolean integrity_check;
  boolean multilevel;
  char *encrypt_key;
  char *output_path;
} command;

void splash() {
  FILE *splash;
  if((splash = fopen("./splash.txt", "r"))) {
    fseek(splash, 0, SEEK_END);
    long file_len = ftell(splash);
    fseek(splash, 0, SEEK_SET);
    char *splash_text = (char *)malloc(sizeof(char) *file_len);
    fread(splash_text, sizeof(char), (size_t)file_len, splash);
    printf("%s\n\n", splash_text);
  } else {
    printf("%s\n%s\n\n", "Welcome to Font Blanc C, Matrix File Encryption", "By Kyle Won");
  }
}

void help() {

}

void clean_instructions(instruction **instructions, int num_instructions) {
  for(int i = 0; i < num_instructions; i++) {
    instruction *cur = instructions[i];
    memset(cur->encrypt_key, '\0', strlen(cur->encrypt_key));
  }
}

// Uses termios to disable terminal echoing and reads encrypt key from user input.
void get_key(char *encrypt_key) {
  printf("Enter key: ");
  struct termios term;
  tcgetattr(fileno(stdin), &term);
  term.c_lflag &= ~ECHO;
  tcsetattr(fileno(stdin), 0, &term);
  if(!fgets(encrypt_key, BUFFER, stdin)) {
    fatal(LOG_OUTPUT, "Error reading key input.");
  }
  printf("\n");
  term.c_lflag |= ECHO;
  tcsetattr(fileno(stdin), 0, &term);
  printf("Key = %s\n", encrypt_key);
}

/*
 * Removes newline character, if it exists, from the end of the given string.
 */
void remove_newline(char *encrypt_key) {
  size_t key_len = strlen(encrypt_key);
  if(*(encrypt_key + (key_len - 1)) == '\n') {
    *(encrypt_key + (key_len - 1)) = '\0';
  }
}

/*
 * Parses options from given argv array and stores in command struct.
 * Retuns 0 if successful, otherwise returns erroneous option.
 */
int read_command(command *com, int argc, char **argv) {
  com->encrypt = -1;
  com->encrypt_key = (char *)calloc(BUFFER, sizeof(char));
  com->output_path = (char *)calloc(BUFFER, sizeof(char));
  com->dimension = 0;
  com->delete_when_done = false;
  com->multilevel = false;
  com->integrity_check = true;
  char error[BUFFER];
  memset(&error, '\0', BUFFER);
  int int_arg;
  // Get opt
  int opt_status = 0;
  // Reset getopt
  optind = 1;
  char *remaining;
  while ((opt_status = getopt(argc, argv, OPTIONS)) != -1) {
    switch (opt_status) {
      case 'e':
        if(com->encrypt >= 0) {
          fatal(LOG_OUTPUT, "Cannot set encrypt flag and decrypt flag at the same time.");
        } else {
          com->encrypt = true;
        }
        break;
      case 'd':
        if(com->encrypt >= 0) {
          fatal(LOG_OUTPUT, "Cannot set encrypt flag and decrypt flag at the same time.");
        }
        com->encrypt = false;
        break;
      case 'D':
        int_arg = (int)strtol(optarg, &remaining, 10);
        if (int_arg > 0) {
          com->dimension = int_arg;
        } else {
          fatal(LOG_OUTPUT, "Dimension argument (-D) must be positive a integer.");
        }
        break;
      case 'k':
        strncpy(com->encrypt_key, optarg, strlen(optarg));
        break;
      case 'o':
        strncpy(com->output_path, optarg, strlen(optarg));
        break;
      case 'x':
        com->delete_when_done = true;
        break;
      case 'm':
        com->multilevel = true;
        break;
      case 's':
        com->integrity_check = false;
        break;
      case 'h':
        // Print help
        help();
        break;
      case ':':
        sprintf(error, "Missing argument for -%c\n", optopt);
        printf("%s\n", error);
        return optopt;
      case '?':
        sprintf(error, "Unknown argument -%c\n", optopt);
        printf("%s\n", error);
        return optopt;
      default:
        break;
    }
  }
  return 0;
}

/*
 * Reads instructions from input and adds them to the given instructions struct. Returns total
 * number of instructions.
 */
int instruction_input_loop(instruction **instructions, int num_instructions) {
  if(!instructions) {
    return num_instructions;
  }
  char *input = (char *)calloc(BUFFER, sizeof(char));
  int argc = 1;
  char **argv = (char **)malloc(sizeof(char *) * 32);
  // set first value of argv NULL as placeholder for cwd
  argv[0] = NULL;
  printf("Enter an instruction using options \"-k\" \"-D\" \"-s\":\n");
  fgets(input, BUFFER, stdin);
  while(strcmp(input, "done\n") != 0) {
    // split input string by spaces
    remove_newline(input);
    char *token = strtok(input, " ");
    while(token != NULL) {
      argv[argc] = token;
      argc += 1;
      token = strtok(NULL, " ");
    }
    command *com = (command *)malloc(sizeof(command));
    int com_status = read_command(com, argc, argv);
    if(com_status != 0) {
      printf("Please re-enter instruction:\n");
    } else {
      if(strlen(com->encrypt_key) == 0) {
        get_key(com->encrypt_key);
      }
      remove_newline(com->encrypt_key);
      instructions[num_instructions] = create_instruction(com->dimension, com->encrypt_key, com->integrity_check);
      num_instructions += 1;
      memset(com->encrypt_key, '\0', strlen(com->encrypt_key));
      printf("Enter an instruction:\n");
    }
    free(com);
    fgets(input, BUFFER, stdin);
  }
  free(input);
  free(argv);
  return num_instructions;
}

int main(int argc, char **argv) {
  clock_t start = clock();
  printf("Start time: %d\n\n", (int) (start *1000 / CLOCKS_PER_SEC));

  // Parse input file path
  char *absolute_path = argv[1];
  char **processed = parse_f_path(absolute_path);
  char *file_name = processed[0];
  char *just_path = processed[1];
  boolean interactive_mode = false;
  instruction **instructions = (instruction **)malloc(sizeof(instruction *) * MAX_INSTRUCTIONS);
  long file_len = get_f_len(absolute_path);
  printf("File name: %s\n", file_name);
  printf("File size: %ld bytes\n\n", file_len);
  command *com = (command *)malloc(sizeof(command));
  int com_status = read_command(com, argc, argv);
  if(com_status != 0) {
    char error[BUFFER];
    sprintf(error, "Fatal error on option -%c. Exiting.\n", com_status);
    fatal(LOG_OUTPUT, error);
  }
  cipher ciph = create_cipher(file_name, just_path, file_len);
  //app welcome
  help();
  if(strlen(com->encrypt_key) == 0) {
    get_key(com->encrypt_key);
  }
  remove_newline(com->encrypt_key);
  instructions[0] = create_instruction(com->dimension, com->encrypt_key, com->integrity_check);
  memset(com->encrypt_key, '\0', strlen(com->encrypt_key));
  int num_instructions = 1;
  // If multilevel encryption flag set, enter instruction input loop
  if(com->multilevel) {
    num_instructions = instruction_input_loop(instructions, num_instructions);
  }
  set_instructions(&ciph, instructions, num_instructions);
  for(int i = 0; i < num_instructions; i++) {
    print_instruction(&ciph, i, com->encrypt);
  }
  if(com->encrypt) {
    printf("Encrypting...\n");
  } else {
    printf("Decrypting...\n");
  }
  int ciph_status = run(&ciph, com->encrypt);
  clean_instructions(instructions, num_instructions);
  close_cipher(&ciph);
  free(com->encrypt_key);
  free(com->output_path);
  free(processed[0]);
  free(processed[1]);
  free(processed);
  free(com);
  clock_t difference = clock() - start;
  double sec = (double)difference / CLOCKS_PER_SEC;
  printf("Elapsed time (s): %.2lf\n", sec);
  printf("Done.\n");
  return ciph_status;
}