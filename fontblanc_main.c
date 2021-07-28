/*
 * fontblanc_main.c
 * Copyrite (c) Kyle Won, 2021
 * Command line user interaction controls for FontBlanc_C. Contains main function.
 */
// Define POSIX source for clock
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include "fontblanc.h"
#include "util.h"
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "Dependencies/csparse.h"
#include <getopt.h>
#include <termios.h>

#define BILLION 1000000000L
#define INIT_OPTIONS "edD:k:o:xmst:hvV"
#define INSTRUCTION_OPTIONS ":k:D:shrp:P"

// Writes elapsed time to a file called fbc_elapsed_time.txt when EXPORT_TIME defined
// Overwrites file on every execution
// Used for performance testing
//#define EXPORT_TIME

/*
 * Prints ASCII art splash.
 */
void splash() {
  if(!verbose_lvl_1 && !verbose_lvl_2) {
    return;
  }
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

/*
 * Prints complete program help.
 */
void main_help() {
  printf("CPME = C Permutation Matrix Encryption\n");
  printf("By Kyle Won\n\n");
  printf("Usage: fontblanc [FILE] -e [OPTIONS...]\t\tencrypt mode\n");
  printf("   or: fontblanc [FILE] -d [OPTIONS...]\t\tdecrypt mode\n");
  printf("\n");
  printf("Arguments:\n");
  printf("   -k\t\tSet encrypt key for first instruction. Expects argument\n");
  printf("   -D\t\tSet matrix dimension for first instruction. If not invoked or 0, defaults to variable-dimension\n");
  printf("   -s\t\tSkip data integrity checks for first instruction. Not recommended\n");
  printf("   -o\t\tSet output filename. If not invoked, defaults to input filename\n");
  printf("   -m\t\tStart program in instruction input loop (multilevel encryption)\n");
  printf("   -t\t\tSet max number of threads to use. If not invoked, defaults to single-threaded\n");
  printf("   -v\t\tVerbose output level I. Prints instructions as they are added\n");
  printf("   -V\t\tVerbose output level II. Prints debugging information\n");
  printf("   -h\t\tDisplay this help and exit\n\n");
  printf("Full documentation at <>\n");
}

/*
 * Prints instruction input loop help.
 */
void instruction_help() {
  printf("Define instructions using the following flags:\n");
  printf("   -k\t\tencryption key (omit flag to enter with terminal echoing disabled)\n");
  printf("   -D\t\tpermutation matrix dimension (defaults to variable-dimension if not invoked or set to 0)\n");
  printf("   -s\t\tskip data integrity checks. Not recommended\n");
  printf("   -r\t\tdelete last instruction\n");
  printf("   -p\t\tprint single instruction at specified position. Expects integer argument\n");
  printf("   -P\t\tprint all instuctions\n");
  printf("   -h\t\tprint instruction input loop help\n");
  printf("   Enter\texecute instructions\n");
  printf("\nExample: \"-k fookeybar -D 0\"\n");
  printf("\n");
}


/*
 * Clears and deallocates memory in given initial_state struct.
 */
void free_init(initial_state *init) {
  memset(init->encrypt_key, '\0', strlen(init->encrypt_key));
  free(init->encrypt_key);
  free(init->output_name);
  free(init);
}

/*
 * Reads initial arguments and set program start state.
 * Returns 0 if successful, otherwise returns erroneous option.
 */
int read_initial_state(initial_state *init, int argc, char **argv) {
  init->encrypt = -1;
  init->encrypt_key = (char *)calloc(BUFFER, sizeof(char));
  init->output_name = (char *)calloc(BUFFER, sizeof(char));
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
        strncpy(init->output_name, optarg, strlen(optarg));
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
        free_init(init);
        exit(EXIT_SUCCESS);
      case 'v':
        verbose_lvl_1 = true;
        break;
      case 'V':
        verbose_lvl_2 = true;
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
int read_instruction_input(command *com, int argc, char **argv) {
  com->encrypt_key = (char *)calloc(BUFFER, sizeof(char));
  com->dimension = -1;
  com->integrity_check = true;
  com->remove_last = false;
  com->print_all = false;
  com->print_single = -1;
  char error[BUFFER];
  memset(error, '\0', BUFFER);
  int int_arg;
  // Get opt
  int opt_status = 0;
  // Reset getopt
  optind = 1;
  char *remaining;
  while ((opt_status = getopt(argc, argv, INSTRUCTION_OPTIONS)) != -1) {
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
      case 'p':
        int_arg = (int)strtol(optarg, &remaining, 10);
        if (int_arg >= 0) {
          com->print_single = int_arg;
        } else {
          fatal(LOG_OUTPUT, "Argument for dimension option (-P) must be a positive integer or 0.");
        }
        break;
      case 'P':
        com->print_all = true;
        break;
      case 'h':
        // Print help
        instruction_help();
        break;
      case ':':
        sprintf(error, "Missing argument for -%c\n", optopt);
        printf("%s", error);
        return optopt;
      case '?':
        sprintf(error, "Unknown argument -%c\n", optopt);
        printf("%s", error);
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
  instruction_help();
  printf("Enter an instruction:\n");
  fgets(input, BUFFER, stdin);
  while(strcmp(input, "\n") != 0) {
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
    int com_status = read_instruction_input(com, argc, argv);
    if(com_status == 0) {
      // Check print options
      if(com->print_all) {
        print_instructions(instructions, num_instructions);
      } else if(com->print_single >= 0) {
        int index = com->print_single - 1;
        if(index < 0 || index >= num_instructions) {
          printf("No instruction numbered %d exists\n\n", com->print_single);
        } else {
          print_instruction_at(instructions, index);
        }
      }
      // Check remove instructions
      if(com->remove_last) {
        num_instructions = remove_last_instruction(instructions, num_instructions);
      }
      // if valid input, create instruction
      if(num_instructions < 10) {
        if(strlen(com->encrypt_key) > 0 || com->dimension >= 0 || !com->integrity_check) {
          if(strlen(com->encrypt_key) == 0) {
            get_key(com->encrypt_key);
          }
          remove_newline(com->encrypt_key);
          instructions[num_instructions] = create_instruction(com->dimension, com->encrypt_key, com->integrity_check);
          num_instructions += 1;
          if(verbose_lvl_1) {
            print_last_instruction(instructions, num_instructions);
          }
        }
      } else if(num_instructions >= 10) {
        // Cannot add new instruction
        printf("Cannot add more than %d instructions.", MAX_INSTRUCTIONS);
      }
    }
    printf("Enter an instruction:\n");
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
  if(!argv[1] || strcmp(argv[1], "-h") == 0) {
    main_help();
    exit(1);
  }
  // Parse input file path
  char *absolute_path = argv[1];
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
    printf("Invalid usage - must specify encrypt (-e) or decrypt (-d) mode.\n");
    exit(1);
  }
  // Set number of threads to 1 if not set
  if(num_threads <= 0) {
    num_threads = 1;
  }
  //app welcome
  splash();
  char **processed = parse_f_path(absolute_path);
  char *file_name = processed[0];
  char *just_path = processed[1];
  printf("File name: %s\n", file_name);
  printf("File size: %ld bytes\n", file_len);
  printf("Mode: %s\n", init->encrypt ? "encrypt" : "decrypt");
  printf("Threads: %d\n", num_threads);
  printf("\n");
  cipher *ciph = create_cipher(file_name, just_path, file_len, init->output_name);
  instruction **instructions = (instruction **)malloc(sizeof(instruction *) * MAX_INSTRUCTIONS);
  int num_instructions = 0;
  // If first instruction included in program execution statement, add to instruction set,
  // else enter instruction input loop
  if(strlen(init->encrypt_key) > 0 || init->dimension >= 0 || !init->integrity_check) {
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
  if(verbose_lvl_1) {
    print_instructions(instructions, num_instructions);
  }
  // If multilevel encryption flag set, enter instruction input loop
  if(init->multilevel) {
    num_instructions = instruction_input_loop(instructions, num_instructions);
  }
  while(num_instructions <= 0) {
    printf("Must add at least one instruction\n\n");
    num_instructions = instruction_input_loop(instructions, num_instructions);
  }
  set_instructions(ciph, instructions, num_instructions);
  if(init->encrypt) {
    printf("Encrypting...\n");
  } else {
    printf("Decrypting...\n");
  }
  long double difference;
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  int ciph_status = run(ciph, init->encrypt);
  clock_gettime(CLOCK_MONOTONIC, &end);
  difference = (long double) (BILLION * (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec)) / (double) BILLION;
  clean_instructions(instructions, num_instructions);
  close_cipher(ciph);
  free_init(init);
  free(processed[0]);
  free(processed[1]);
  free(processed);
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