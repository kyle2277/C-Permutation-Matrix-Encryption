/*
 * fontblanc_main.c
 * Copyrite (c) Kyle Won, 2021
 * Command line user interaction controls for FontBlanc_C. Contains main function.
 */
// Include POSIX source for clock
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include "fontblanc.h"
#include "util.h"
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "Dependencies/csparse.h"
#include <getopt.h>
#include <termios.h>

#define INIT_OPTIONS "iedD:k:o:xmst:h"
#define COMMAND_OPTIONS ":k:D:shr"
#define BILLION 1000000000L
#define EXPORT_TIME

/*
 * Prints ASCII art splash.
 */
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

void usage_help() {
  printf("Print usage help here.\n");
}
void main_help() {
  printf("Print help here\n");
}
void instruction_help() {
  printf("Print instruction help here\n");
}

/*
 * Reads initial arguments and set program start state.
 * Returns 0 if successful, otherwise returns erroneous option.
 */
int read_initial_state(initial_state *init, int argc, char **argv) {
  init->encrypt = -1;
  init->encrypt_key = (char *)calloc(BUFFER, sizeof(char));
  init->output_path = (char *)calloc(BUFFER, sizeof(char));
  init->dimension = 0;
  init->delete_when_done = false;
  init->multilevel = false;
  init->integrity_check = true;
  char error[BUFFER];
  memset(error, '\0', BUFFER);
  int int_arg;
  // Get opt
  int opt_status = 0;
  char *remaining;
  while ((opt_status = getopt(argc, argv, INIT_OPTIONS)) != -1) {
    switch (opt_status) {
      case 'e':
        if(init->encrypt >= 0) {
          fatal(LOG_OUTPUT, "Invalid usage - cannot set encrypt flag and decrypt flag at the same time.");
        } else {
          init->encrypt = true;
        }
        break;
      case 'd':
        if(init->encrypt >= 0) {
          fatal(LOG_OUTPUT, "Invalid usage - cannot set encrypt flag and decrypt flag at the same time.");
        }
        init->encrypt = false;
        break;
      case 'D':
        int_arg = (int)strtol(optarg, &remaining, 10);
        if (int_arg >= 0) {
          init->dimension = int_arg;
        } else {
          fatal(LOG_OUTPUT, "Argument for dimension option (-D) must be a positive integer or 0.");
        }
        break;
      case 'k':
        strncpy(init->encrypt_key, optarg, strlen(optarg));
        break;
      case 'o':
        strncpy(init->output_path, optarg, strlen(optarg));
        break;
      case 'x':
        init->delete_when_done = true;
        break;
      case 'm':
        init->multilevel = true;
        break;
      case 's':
        init->integrity_check = false;
        break;
      case 't':
        int_arg = (int)strtol(optarg, &remaining, 10);
        if (int_arg > 0) {
          num_threads = int_arg;
        } else {
          fatal(LOG_OUTPUT, "Argument for thread option (-t) must be a positive integer.");
        }
        break;
      case 'h':
        // Print main help
        main_help();
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
        printf("DEFAULT\n");
        break;
    }
  }
  return 0;
}

/*
 * Parses options from given argv array and stores in command struct.
 * Retuns 0 if successful, otherwise returns erroneous option.
 */
int read_command(command *com, int argc, char **argv) {
  com->encrypt_key = (char *)calloc(BUFFER, sizeof(char));
  com->dimension = -1;
  com->integrity_check = true;
  com->remove_last = false;
  com->help = false;
  char error[BUFFER];
  memset(error, '\0', BUFFER);
  int int_arg;
  // Get opt
  int opt_status = 0;
  // Reset getopt
  optind = 1;
  char *remaining;
  while ((opt_status = getopt(argc, argv, COMMAND_OPTIONS)) != -1) {
    switch (opt_status) {
      case 'D':
        int_arg = (int)strtol(optarg, &remaining, 10);
        if (int_arg >= 0) {
          com->dimension = int_arg;
        } else {
          fatal(LOG_OUTPUT, "Argument for dimension option (-D) must be a positive integer or 0.");
        }
        break;
      case 'k':
        strncpy(com->encrypt_key, optarg, strlen(optarg));
        break;
      case 's':
        com->integrity_check = false;
        break;
      case 'r':
        com->remove_last = true;
        break;
      case 'h':
        // Print help
        com->help = true;
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
        printf("DEFAULT\n");
        break;
    }
  }
  return 0;
}

/*
 * Reads instructions from input until user types "done" and adds them to the given.
 * instructions struct. Returns total number of instructions.
 */
int instruction_input_loop(instruction **instructions, int num_instructions) {
  if(!instructions) {
    return num_instructions;
  }
  char *input = (char *)calloc(BUFFER, sizeof(char));
  char **argv = (char **)malloc(sizeof(char *) * 32);
  // set first value of argv NULL as placeholder for cwd
  argv[0] = NULL;
  printf("\nEnter an instruction using options \"-k\" \"-D\" \"-s\":\n");
  fgets(input, BUFFER, stdin);
  while(strcmp(input, "done\n") != 0) {
    // split input string by spaces
    remove_newline(input);
    int argc = 1;
    char *token = strtok(input, " ");
    while(token != NULL) {
      argv[argc] = token;
      argc += 1;
      token = strtok(NULL, " ");
    }
    command *com = (command *)malloc(sizeof(command));
    int com_status = read_command(com, argc, argv);
    if(com_status != 0) {
      printf("Re-enter instruction:\n");
    } else if (com->help) {
      instruction_help();
      printf("\nEnter an instruction:\n");
    } else {
      if(com->remove_last && num_instructions > 0) {
        // Remove last instruction
        instruction *remove = instructions[num_instructions - 1];
        memset(remove->encrypt_key, '\0', strlen(remove->encrypt_key));
        free(remove);
        num_instructions -= 1;
        printf("Removed instruction #%d\n", num_instructions + 1);
      } else if(com->remove_last && num_instructions <= 0) {
        // Cannot remove last instruction
        printf("No previous instruction to remove\n");
      } else if(num_instructions < 10) {
        // Check input is valid
        if(strlen(com->encrypt_key) > 0 || com->dimension >= 0 || !com->integrity_check) {
          if(strlen(com->encrypt_key) == 0) {
            get_key(com->encrypt_key);
          }
          remove_newline(com->encrypt_key);
          instructions[num_instructions] = create_instruction(com->dimension, com->encrypt_key, com->integrity_check);
          num_instructions += 1;
        } else {
          printf("Invalid instruction\n");
        }
      } else if(num_instructions >= 10) {
        // Cannot add new instruction
        printf("Cannot add more than %d instructions.", MAX_INSTRUCTIONS);
      }
      print_instructions(instructions, num_instructions);
      printf("\nEnter an instruction:\n");
    }
    memset(com->encrypt_key, '\0', strlen(com->encrypt_key));
    free(com->encrypt_key);
    free(com);
    fgets(input, BUFFER, stdin);
  }
  free(input);
  free(argv);
  return num_instructions;
}

/*
 * Facilitates generating instructions and running cipher.
 */
int main(int argc, char **argv) {
  if(!argv[1]) {
    usage_help();
    exit(1);
  }
  // Parse input file path
  char *absolute_path = argv[1];
  char **processed = parse_f_path(absolute_path);
  char *file_name = processed[0];
  char *just_path = processed[1];
  long file_len = get_f_len(absolute_path);
  // Check if input file exists
  if(file_len < 0) {
    char error[BUFFER];
    snprintf(error, BUFFER, "File \"%s\" not found. First argument must be a file.", absolute_path);
    fatal(LOG_OUTPUT, error);
  }
  initial_state *init = (initial_state *)malloc(sizeof(initial_state));
  int init_status = read_initial_state(init, argc, argv);
  // Check for getopt errors
  if(init_status != 0) {
    free(init);
    char error[BUFFER];
    snprintf(error, BUFFER, "Fatal error on option -%c. Exiting.\n", init_status);
    fatal(LOG_OUTPUT, error);
  }
  // Check if mode specified
  if(init->encrypt < 0) {
    free(init);
    usage_help();
    exit(1);
    //fatal(LOG_OUTPUT, "Invalid usage - must specify encrypt (-e) or decrypt (-d) mode.");
  }
  // Set number of threads to 1 if not set
  if(num_threads <= 0) {
    num_threads = 1;
  }
  printf("File name: %s\n", file_name);
  printf("File size: %ld bytes\n", file_len);
  printf("Mode: %s\n", init->encrypt ? "encrypt" : "decrypt");
  printf("Threads: %d\n", num_threads);
  cipher *ciph = create_cipher(file_name, just_path, file_len);
  //app welcome
  main_help();
  instruction **instructions = (instruction **)malloc(sizeof(instruction *) * MAX_INSTRUCTIONS);
  int num_instructions = 0;
  // If first instruction included in program execution statement, add to instruction set,
  // else enter instruction input loop
  if(strlen(init->encrypt_key) > 0 || init->dimension > 0 || !init->integrity_check) {
    // Check if need key input
    if(strlen(init->encrypt_key) == 0) {
      get_key(init->encrypt_key);
    }
    remove_newline(init->encrypt_key);
    instructions[0] = create_instruction(init->dimension, init->encrypt_key, init->integrity_check);
    num_instructions += 1;
    memset(init->encrypt_key, '\0', strlen(init->encrypt_key));
  } else {
    init->multilevel = true;
  }
  print_instructions(instructions, num_instructions);
  // If multilevel encryption flag set, enter instruction input loop
  if(init->multilevel) {
    num_instructions = instruction_input_loop(instructions, num_instructions);
  }
  while(num_instructions <= 0) {
    printf("\nMust add at least one instruction\n");
    num_instructions = instruction_input_loop(instructions, num_instructions);
  }
  set_instructions(ciph, instructions, num_instructions);
  if(init->encrypt) {
    printf("\nEncrypting...\n");
  } else {
    printf("\nDecrypting...\n");
  }
  long double difference;
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int ciph_status = run(ciph, init->encrypt);
  clock_gettime(CLOCK_MONOTONIC, &end);
  difference = (long double) (BILLION * (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)) / (double) BILLION;
  //double sec = (double)difference / CLOCKS_PER_SEC;
  clean_instructions(instructions, num_instructions);
  close_cipher(ciph);
  free(init->encrypt_key);
  free(init->output_path);
  free(processed[0]);
  free(processed[1]);
  free(processed);
  free(init);
  free_instructions(instructions, num_instructions);
  printf("Elapsed time (s): %Lf\n", difference);
#ifdef EXPORT_TIME
  FILE *time_out = fopen("fbc_elapsed_time.txt", "w");
  char write[BUFFER];
  snprintf(write, BUFFER, "%Lf", difference);
  fwrite(write, sizeof(char), strlen(write), time_out);
  fclose(time_out);
#endif
  printf("Done.\n");
  return ciph_status;
}