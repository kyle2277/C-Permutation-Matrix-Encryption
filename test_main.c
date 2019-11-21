//
// Created by kylej on 6/14/19.
//
#include <stdio.h>
#include <stdlib.h>
#include "fontblanc.h"
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "Dependencies/csparse.h"
#include "Dependencies/st_io.h"

#define BUFFER 255
#define MAX_INSTRUCTIONS 10

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
    printf("%s\n%s\n", "Add instructions in form of:", "-add <fixed/flexible> <dimension (0 if flexible)> <encrypt key>");
    printf("%s\n", "Run process with -run");
    printf("%s\n", "Show commands with -help");
    printf("%s\n\n", "Exit program with -quit");
}

void clean_instructions(instruction **instructions, int num_instructions) {
    for(int i = 0; i < num_instructions; i++) {
        instruction *cur = instructions[i];
        memset(cur->encrypt_key, '\0', strlen(cur->encrypt_key));
    }
}

int parse_instruction(char command[], instruction **instructions, int num_instructions) {
    int max_args = 4;
    //get rid of line break character
    command[strlen(command)-1] = '\0';
    char *args[max_args];
    char *delimiter = " ";
    char *token = strtok(command, delimiter);
    int token_count = 0;
    args[token_count] = token;
    while(token != NULL) {
        token_count++;
        token = strtok(NULL, delimiter);
        if(token_count > max_args) {
            printf("%s\n", "Too many arguments.");
            return num_instructions;
        }
        if(token != NULL) {
            args[token_count] = token;
        }
    }
    if(token_count < max_args) {
        printf("%s\n", "Too few arguments.");
        return num_instructions;
    }
    char *fixed = args[1];
    int dimension = (int)strtol(args[2], (char **)NULL, 10);
    char *encrypt_key = args[3];\
    // error checking
    if((strlen(encrypt_key) < 5) || strlen(encrypt_key) > 20) {
        // return error
        char *error_msg = strlen(encrypt_key) < 5 ? "less than 5 " : "greater than 20 ";
        printf("%s%s%s\n\n", "Key cannot be ", error_msg, "characters.");
        return num_instructions;
    }
    if(!(strcmp(fixed, "fixed") == 0 || strcmp(fixed, "flexible") == 0) ||
        (strcmp(fixed, "fixed") == 0 && dimension == 0)) {
       printf("%s\n\n","Invalid type. Must be \"fixed\" or \"flexible.\"");
       return num_instructions;
    }
    if(strcmp(fixed, "flexible") == 0) {
        dimension = 0;
    }
    num_instructions++;
    instructions[num_instructions-1] = create_instruction(dimension, encrypt_key);
    memset(args[3], '\0', sizeof(char)*strlen(args[3]));
    printf("Instruction added.\n");
    return num_instructions;
}

int main(int args, char *argv[]) {
//    FILE *f_vals = fopen("key_vals.csv", "w");
//    char *keys[22] = {"zaqxs","zaqxsw","zaqxswc","zaqxswcd","zaqxswcde","zaqxswcdev","zaqxswcdevf","zaqxswcdevfr","zaqxswcdevfrb",
//                      "zaqxswcdevfrbg","zaqxswcdevfrbgt","zaqxswcdevfrbgtn","zaqxswcdevfrbgtnh","zaqxswcdevfrbgtnhy",
//                      "zaqxswcdevfrbgtnhym","zaqxswcdevfrbgtnhymj","zaqxswcdevfrbgtnhymju","zaqxswcdevfrbgtnhymju<",
//                      "zaqxswcdevfrbgtnhymju<k","zaqxswcdevfrbgtnhymju<ki","zaqxswcdevfrbgtnhymju<ki>","zaqxswcdevfrbgtnhymju<ki>l"};
//    for(int i = 0; i < 22; i++) {
//        char *key = keys[i];
//        if(key != '\0') {
//            int sum = key_sum(key);
//            char *write = (char *) malloc(sizeof(char) * 120);
//            sprintf(write, "%d,%lf\n", sum, log(sum));
//            fwrite(write, sizeof(char), strlen(write), f_vals);
//        }
//    }
//    fclose(f_vals);
//    exit(0);
    clock_t start = clock();
    char *EorD = argv[2];
    boolean e = strcmp("encrypt", EorD) == 0;
    if(!e && strcmp("decrypt", EorD) != 0) {
        fatal(LOG_OUTPUT, "Invalid action.");
    }
    splash();
    printf("Start time: %d\n\n", (int) (start *1000 / CLOCKS_PER_SEC));
    char *absolute_path = argv[1];
    char **processed = parse_f_path(absolute_path);
    char *file_name = processed[0];
    char *just_path = processed[1];
    long file_len;
    if(e) { //encrypt
        file_len = get_f_len(absolute_path);
    } else { //decrypt
        char *full_path = (char *)malloc(sizeof(char)*256);
        sprintf(full_path, "%s%s%s%s", just_path, ENCRYPT_TAG, file_name, ENCRYPT_EXT);
        file_len = get_f_len(full_path);
    }
    cipher c = create_cipher(file_name, just_path, file_len);
    free(processed);
    //app welcome
    printf("%s%s\n%s%ld%s\n%s%s\n\n", "File name: ", c.file_name, "File size: ", file_len, " Bytes", "Mode: ", e ? "encrypt" : "decrypt");
    help();
    char command[BUFFER];
    int num_instructions = 0;
    instruction **instructions = (instruction **)malloc(sizeof(instruction *)*MAX_INSTRUCTIONS);
    while(true) {
        fgets(command, BUFFER, stdin);
        if(strstr(command, "-run")) {
            if(num_instructions <= 0) {
                fatal(LOG_OUTPUT, "No instructions added.");
            }
            break;
        } else if(strstr(command, "-quit")) {
            clean_instructions(instructions, num_instructions);
            exit(0);
        } else if(strstr(command, "-add")) {
            num_instructions = parse_instruction(command, instructions, num_instructions);
        } else if(strstr(command, "-help")) {
            help();
        } else {
            printf("Command not recognized.\n");
        }
    }
    set_instructions(&c, instructions, num_instructions);
    if(e) {
        printf("Encrypting...\n");
    } else {
        printf("Decrypting...\n");
    }
    int status = run(&c, e);
    clean_instructions(instructions, num_instructions);
    close_cipher(&c);
    clock_t difference = clock() - start;
    double sec = (double)difference / CLOCKS_PER_SEC;
    printf("Elapsed time (s): %.2lf\n", sec);
    return status;
}


