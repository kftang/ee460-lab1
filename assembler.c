#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INT_16_MAX        65535
#define MAX_LINE_LENGTH   255
#define MAX_LABEL_LENGTH  20
#define MAX_OPCODE_LENGTH 6
#define MAX_SYMBOLS       255
#define HEX_STRING_LENGTH 7

enum asm_state_t {
  INITIAL, ORIG_SET, END
};

enum line_state_t {
  OK, EMPTY_LINE, ERROR
};

// Operand types can be register, immediate, or a label
enum operand_type_t {
  REGISTER = 0x01,
  IMMEDIATE = 0x02,
  LABEL = 0x04
};

struct label_t {
  char              name[MAX_LABEL_LENGTH];
  uint16_t          address;
};

struct assembler_state_t {
  enum asm_state_t  state;
  uint16_t          cur_address;
  uint16_t          orig_address;
  struct label_t    *sym_table[MAX_SYMBOLS];
  int               num_labels;
};

struct parsed_asm_t {
  bool              valid_asm;
  int               error_code;
  uint16_t          machine_code;
};

struct parsed_num_t {
  bool              valid_num;
  int16_t           num;
};

struct asm_line_t {
  enum line_state_t state;
  bool              valid_line;
  char              *label_name;
  char              *opcode;
  char              *operand1;
  char              *operand2;
  char              *operand3;
};

// Global variables
struct assembler_state_t asm_state;

char valid_opcodes[43][6] = {
  "add", "and", "br", "jmp", "jsr", "jsrr", "ldb", "ldw",
  "lea", "nop", "not", "ret", "lshf", "rshfl", "rshfa", "rti", "stb",
  "stw", "trap", "xor", "halt", "in", "out", "getc", "puts",
  "brn", "brz", "brp", "brnz", "brnp", "brzp", "brnzp",
  "brzn", "brpn", "brpz", "brzpn", "brznp", "brpzn", "brpnz", "brnpz",
  ".orig", ".end", ".fill"
};

int num_operands[43] = {
  3, 3, 1, 1, 1, 1, 3, 3,
  2, 0, 2, 0, 3, 3, 3, 0, 3,
  3, 1, 3, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 0, 1
};

int immediate_bits[43] = {
  5, 5, 9, 0, 11, 0, 6, 6,
  9, 0, 0, 0, 4, 4, 4, 0, 6,
  6, 8, 5, 0, 0, 0, 0, 0,
  9, 9, 9, 9, 9, 9,
  9, 9, 9, 9, 9, 9, 9,
  16, 0, 16
};

int16_t immediate_min_max[43][2] = {
  { -16, 15 }, { -16, 15 }, { -256, 255 },  {}, { -1024, 1023 }, {}, { -32, 31 }, { -32, 31},
  { -256, 255 }, {}, {}, {}, { 0, 15 }, { 0, 15 }, { 0, 15 }, {},  { -32, 31 },
  { -32, 31 }, { 0, 255 }, { -16, 15 }, {}, {}, {}, {}, {},
  { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, 
  { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255 }, { -256, 255},
  { -32768, 32767 }, {}, { -32768, 32767 }
};

uint16_t immediate_masks[43] = {
  0x001f, 0x001f, 0x01ff, 0x0000, 0x07ff, 0x0000, 0x003f, 0x003f,
  0x01ff, 0x0000, 0x0000, 0x0000, 0x000f, 0x000f, 0x000f, 0x0000, 0x003f,
  0x003f, 0x00ff, 0x001f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff, 
  0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff, 0x01ff
};

uint16_t instruction_opcode[43] = {
  0x1000, 0x5000, 0x0000, 0xb000, 0x4000, 0x4000, 0x2000, 0x6000,
  0xe000, 0x0000, 0x9000, 0xb000, 0xc000, 0xc000, 0xc000, 0x8000, 0x3000,
  0x7000, 0xf000, 0x9000, 0xf000, 0xf000, 0xf000, 0xf000, 0xf000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
  0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};

enum operand_type_t valid_types[43][3] = {
  { REGISTER, REGISTER, REGISTER | IMMEDIATE },
  { REGISTER, REGISTER, REGISTER | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { REGISTER },
  { LABEL | IMMEDIATE },
  { REGISTER },
  { REGISTER, REGISTER, IMMEDIATE },
  { REGISTER, REGISTER, IMMEDIATE },
  { REGISTER, LABEL | IMMEDIATE },
  { },
  { REGISTER, REGISTER },
  { },
  { REGISTER, REGISTER, IMMEDIATE },
  { REGISTER, REGISTER, IMMEDIATE },
  { REGISTER, REGISTER, IMMEDIATE },
  { },
  { REGISTER, REGISTER, IMMEDIATE },
  { REGISTER, REGISTER, IMMEDIATE },
  { IMMEDIATE },
  { REGISTER, REGISTER, REGISTER | IMMEDIATE },
  { }, { }, { }, { }, { },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { LABEL | IMMEDIATE },
  { IMMEDIATE },
  { },
  { IMMEDIATE }
};

int num_opcodes = sizeof(valid_opcodes) / sizeof(valid_opcodes[0]);

struct asm_line_t * tokenize_line(char *asm_str) {
  // Allocate memory for return struct and initialize
  struct asm_line_t *asm_line = (struct asm_line_t *) malloc(sizeof(struct asm_line_t));
  asm_line->state = OK;
  asm_line->valid_line = true;
  asm_line->label_name = NULL;
  asm_line->opcode = NULL;
  asm_line->operand1 = NULL;
  asm_line->operand2 = NULL;
  asm_line->operand3 = NULL;

  // Iterate through tokens
  char *token = strtok(asm_str, " \t,\n");

  // If token is empty, or starts with comment, mark line as empty
  if (token == NULL || *token == ';') {
    asm_line->state = EMPTY_LINE;
    return asm_line;
  }

  // Check if first token is an opcode
  for (int i = 0; i < num_opcodes; i++) {
    // If the token is an opcode, copy the opcode into the struct
    if (strcmp(valid_opcodes[i], token) == 0) {
      asm_line->opcode = (char *) malloc(sizeof(char) * (strlen(valid_opcodes[i]) + 1));
      strcpy(asm_line->opcode, valid_opcodes[i]);
    }
  }

  // If opcode is null here, first token is a label so set label name and opcode
  if (asm_line->opcode == NULL) {
    asm_line->label_name = (char *) malloc(sizeof(char) * (strlen(token) + 1));
    strcpy(asm_line->label_name, token);

    // Now find opcode
    token = strtok(NULL, " \t,\n");

    // Make sure token exists, otherwise return invalid line
    if (token == NULL) {
      // Free label name
      free(asm_line->label_name);
      asm_line->label_name = NULL;

      // Set line to invalid
      asm_line->valid_line = false;
      return asm_line;
    }

    // Find opcode
    for (int i = 0; i < num_opcodes; i++) {
      // If the token is an opcode, copy the opcode into the struct
      if (strcmp(valid_opcodes[i], token) == 0) {
        asm_line->opcode = (char *) malloc(sizeof(char) * (strlen(valid_opcodes[i]) + 1));
        strcpy(asm_line->opcode, valid_opcodes[i]);
      }
    }

    // Make sure opcode was populated, otherwise opcode is invalid
    if (asm_line->opcode == NULL) {
      // Free label name
      free(asm_line->label_name);
      asm_line->label_name = NULL;

      // Set line to invalid
      asm_line->valid_line = false;
      return asm_line;
    }
  }

  // Store operands and stop when comment reached or end of line
  token = strtok(NULL, " \t,\n");
  if (token != NULL && *token != ';') {
    asm_line->operand1 = (char *) malloc(sizeof(char) * (strlen(token) + 1));
    strcpy(asm_line->operand1, token);

    // Check operand 2
    token = strtok(NULL, " \t,\n");
    if (token != NULL && *token != ';') {
      asm_line->operand2 = (char *) malloc(sizeof(char) * (strlen(token) + 1));
      strcpy(asm_line->operand2, token);

      // Check operand 3
      token = strtok(NULL, " \t,\n");
      if (token != NULL && *token != ';') {
        asm_line->operand3 = (char *) malloc(sizeof(char) * (strlen(token) + 1));
        strcpy(asm_line->operand3, token);
      }
      // After 3 opereands, the next token can only be valid if it is a comment
      token = strtok(NULL, " \t,\n");
      if (token != NULL && *token != ';') {
        // Free everything in the return struct and set to NULL
        if (asm_line->label_name != NULL)
          free(asm_line->label_name);
        free(asm_line->opcode);
        free(asm_line->operand1);
        free(asm_line->operand2);
        free(asm_line->operand3);
        asm_line->label_name = NULL;
        asm_line->opcode = NULL;
        asm_line->operand1 = NULL;
        asm_line->operand2 = NULL;
        asm_line->operand3 = NULL;

        // Set line to invalid
        asm_line->valid_line = false;
        return asm_line;
      }
    }
  }

  return asm_line;
}

struct parsed_num_t * parse_num(char *asm_num) {
  struct parsed_num_t *parsed_num = malloc(sizeof(struct parsed_num_t));
  parsed_num->valid_num = true;
  parsed_num->num = 0;

  int asm_num_length = strlen(asm_num);

  // Make sure string is a valid asm number
  if (asm_num_length < 2) {
    parsed_num->valid_num = false;
    return parsed_num;
  }
  if (*asm_num == '#') {
    // Make sure characters in # are valid for a decimal number
    for (int i = 1; i < asm_num_length; i++) {
      if (asm_num[i] != '-' && (asm_num[i] < '0' || asm_num[i] > '9')) {
        printf("invalid number\n");
        parsed_num->valid_num = false;
        return parsed_num;
      }
    }
    
    // Convert string to number
    long converted_num = strtol(asm_num + 1, NULL, 10);
    if (converted_num > INT_16_MAX) {
      printf("number greater than 16 bits\n");
      parsed_num->valid_num = false;
      return parsed_num;
    }
    parsed_num->num = (int16_t) converted_num;
  } else if (*asm_num == 'x') {
    // Make sure characters after x are valid for a hex number
    for (int i = 1; i < asm_num_length; i++) {
      if (asm_num[i] != '-' && (asm_num[i] < '0' || asm_num[i] > '9') && (asm_num[i] < 'a' || asm_num[i] > 'f')) {
        printf("invalid hex number\n");
        parsed_num->valid_num = false;
        return parsed_num;
      }
    }
    
    // Convert string to number
    long converted_num = strtol(asm_num + 1, NULL, 16);
    if (converted_num > INT_16_MAX) {
      printf("number greater than 16 bits\n");
      parsed_num->valid_num = false;
      return parsed_num;
    }
    parsed_num->num = (int16_t) converted_num;
  } else {
    parsed_num->valid_num = false;
    return parsed_num;
  }

  return parsed_num;
}

struct label_t * get_label(char *label_name) {
  for (int i = 0; i < MAX_SYMBOLS && asm_state.sym_table[i] != NULL; i++) {
    if (strcmp(asm_state.sym_table[i]->name, label_name) == 0) {
      return asm_state.sym_table[i];
    }
  }
  return NULL;
}

uint16_t parse_register(char *register_name) {
  return register_name[1] - '0';
}

void free_asm_line(struct asm_line_t *asm_line) {
  if (asm_line->opcode != NULL)
    free(asm_line->opcode);
  if (asm_line->label_name != NULL)
    free(asm_line->label_name);
  if (asm_line->operand1 != NULL)
    free(asm_line->operand1);
  if (asm_line->operand2 != NULL)
    free(asm_line->operand2);
  if (asm_line->operand3 != NULL)
    free(asm_line->operand3);
  free(asm_line);
}

bool is_register(char *token) {
  if (strlen(token) != 2 || *token != 'r' || token[1] < '0' || token[1] > '7')
    return false;
  return true;
}

bool is_label(char *token) {
  int token_len = strlen(token);
  if (token_len > 20 || *token == 'x')
    return false;
  for (int i = 0; i < token_len; i++) {
    if ((token[i] > '9' || token[i] < '0') && (token[i] > 'z' || token[i] < 'a'))
      return false;
  }
  return true;
}

bool is_immediate(char *token) {
  struct parsed_num_t *parsed_num = parse_num(token);
  if (!parsed_num->valid_num) {
    free(parsed_num);
    return false;
  }
  free(parsed_num);
  return true;
}

bool check_operand_type(int opcode_number, char *operand, int operand_num) {
  enum operand_type_t operand_type = valid_types[opcode_number][operand_num - 1];
  if (operand_type & REGISTER && is_register(operand)) {
    return true;
  }
  if (operand_type & IMMEDIATE && is_immediate(operand)) {
    return true;
  }
  if (operand_type & LABEL && is_label(operand)) {
    return true;
  }
  printf("Operand %d was expected to be %d\n", operand_num, operand_type);
  return false;
}

bool validate_asm_line(struct asm_line_t *asm_line) {
  if (asm_line->opcode == NULL)
    return false;
    
  // Find the operand number corresponding to the entry in the static array
  int opcode_number = -1;
  for (int i = 0; i < num_opcodes; i++) {
    if (strcmp(valid_opcodes[i], asm_line->opcode) == 0) {
      opcode_number = i;
      break;
    }
  }
  
  int max_operands = num_operands[opcode_number];

  // Verify # of operands and type
  switch (max_operands) {
    case 0:
      if (asm_line->operand1 != NULL) {
        printf("Expected no operands but one was supplied\n");
        return false;
      }
      break;
    case 1:
      if (asm_line->operand2 != NULL || asm_line->operand1 == NULL) {
        printf("Missing operand 1 or operand 2 was supplied when only 1 expected\n");
        return false;
      }
      if (!check_operand_type(opcode_number, asm_line->operand1, 1))
        return false;
      break;
    case 2:
      if (asm_line->operand3 != NULL || asm_line->operand2 == NULL) {
        printf("Missing operand 2 or operand 3 was supplied when only 2 expected\n");
        return false;
      }
      if (!check_operand_type(opcode_number, asm_line->operand1, 1))
        return false;
      if (!check_operand_type(opcode_number, asm_line->operand2, 2))
        return false;
      break;
    case 3:
      if (asm_line->operand3 == NULL) {
        printf("Missing operand 3\n");
        return false;
      }
      if (!check_operand_type(opcode_number, asm_line->operand1, 1))
        return false;
      if (!check_operand_type(opcode_number, asm_line->operand2, 2))
        return false;
      if (!check_operand_type(opcode_number, asm_line->operand3, 3))
        return false;
  }
  return true;
}

struct parsed_asm_t * parse_asm(struct asm_line_t *asm_line) {
  // Allocate memory for return struct
  struct parsed_asm_t *parsed_asm = (struct parsed_asm_t *) malloc(sizeof(struct parsed_asm_t));
  parsed_asm->valid_asm = true;
  parsed_asm->machine_code = 0x0000;

  // If assembler state is END, skip the line since the program has finished
  if (asm_state.state == END) {
    asm_line->state = EMPTY_LINE;
    return parsed_asm;
  }

  // If assembler state is not ORIG_SET before first instruction, error
  if (asm_state.state != ORIG_SET && strcmp(asm_line->opcode, ".orig") != 0) {
    printf("An instruction was read before .orig was set\n");
    parsed_asm->valid_asm = false;
    parsed_asm->error_code = 4;
    return parsed_asm;
  }

  // Check if opcode is orig
  if (strcmp(asm_line->opcode, ".orig") == 0) {
    // Set assembler state
    asm_state.state = ORIG_SET;

    // Parse the orig address and set machine code to the address
    struct parsed_num_t *parsed_num = parse_num(asm_line->operand1);
    parsed_asm->machine_code = parsed_num->num;
    free(parsed_num);
    return parsed_asm;
  }

  // Check if opcode is end
  if (strcmp(asm_line->opcode, ".end") == 0) {
    asm_state.state = END;
    asm_line->state = EMPTY_LINE;
    return parsed_asm;
  }

  // Find the operand number corresponding to the entry in the static array
  int opcode_number = -1;
  for (int i = 0; i < num_opcodes; i++) {
    if (strcmp(valid_opcodes[i], asm_line->opcode) == 0) {
      opcode_number = i;
      break;
    }
  }
  
  // Set machine code to the opcode, we will build on this
  parsed_asm->machine_code = instruction_opcode[opcode_number];

  // Get immediate mask for this opcode
  uint16_t immediate_mask = immediate_masks[opcode_number];
  int16_t min = immediate_min_max[opcode_number][0];
  int16_t max = immediate_min_max[opcode_number][1];
  int shift_bits = 16 - immediate_bits[opcode_number];
  switch (opcode_number) {
    // add, and, xor all have the same mapping
    case 0:
    case 1:
    case 19: {
      uint16_t dr = parse_register(asm_line->operand1) << 9;
      uint16_t sr1 = parse_register(asm_line->operand2) << 6;
      parsed_asm->machine_code |= (dr | sr1);
      if (is_register(asm_line->operand3)) {
        uint16_t sr2 = parse_register(asm_line->operand3);
        parsed_asm->machine_code |= sr2;
      } else {
        // Set immediate bit
        parsed_asm->machine_code |= 0x0020;

        // Parse immediate # from operand
        struct parsed_num_t *parsed_num = parse_num(asm_line->operand3);
        int16_t immediate = parsed_num->num;
        free(parsed_num);

        // Check if immediate is between valid min/max
        if (immediate < min || immediate > max) {
          parsed_asm->valid_asm = false;
          parsed_asm->error_code = 3;
          return parsed_asm;
        }

        // If immediate is negative, we need to remove the leading 1s
        uint16_t unsigned_immediate = immediate;
        if (immediate < 0) {
          unsigned_immediate <<= shift_bits;
          unsigned_immediate >>= shift_bits;
        }
        parsed_asm->machine_code |= unsigned_immediate;
      }
      break;
    }

    // All cases of br
    case 2:
    case 25:
    case 26:
    case 27:
    case 28:
    case 29:
    case 30:
    case 31: 
    case 32: 
    case 33: 
    case 34: 
    case 35: 
    case 36: 
    case 37: 
    case 38: 
    case 39: {
      // Figure out which condition codes to branch on
      int opcode_len = strlen(asm_line->opcode);
      for (int i = 2; i < opcode_len; i++) {
        if (asm_line->opcode[i] == 'n')
          parsed_asm->machine_code |= 0x0800;
        if (asm_line->opcode[i] == 'z')
          parsed_asm->machine_code |= 0x0400;
        if (asm_line->opcode[i] == 'p')
          parsed_asm->machine_code |= 0x0200;
      }

      int16_t offset;

      // If offset is a label, convert it into an offset
      if (is_label(asm_line->operand1)) {
        struct label_t *label = get_label(asm_line->operand1);
        if (label == NULL) {
          parsed_asm->valid_asm = false;
          parsed_asm->error_code = 1;
          return parsed_asm;
        }
        offset = label->address - asm_state.cur_address;

      // Otherwise parse offset from operand
      } else {
        struct parsed_num_t *parsed_num = parse_num(asm_line->operand1);
        offset = parsed_num->num;
        free(parsed_num);
      }

      // Check that the offset is a valid range
      if (offset < min || offset > max) {
        parsed_asm->valid_asm = false;
        parsed_asm->error_code = 3;
        return parsed_asm;
      }

      // If immediate is negative, we need to remove the leading 1s
      uint16_t unsigned_offset = offset;
      if (offset < 0) {
        unsigned_offset <<= shift_bits;
        unsigned_offset >>= shift_bits;
      }

      parsed_asm->machine_code |= unsigned_offset;
      break;
    }

    // jmp and jsrr have same mapping
    case 3:
    case 5: {
      uint16_t base = parse_register(asm_line->operand1) << 6;
      printf("base: %d\n", base);
      parsed_asm->machine_code |= base;
      break;
    }

    // jsr has no shared mapping
    case 4: {
      break;
    }

    // ldb, ldw, stb, stw have same mapping
    case 6:
    case 7:
    case 16:
    case 17: {
      uint16_t dr = parse_register(asm_line->operand1) << 9;
      uint16_t base = parse_register(asm_line->operand2) << 6;
      printf("dr: %d\nbase: %d\n", dr, base);
      parsed_asm->machine_code |= (dr | base);

      // Parse immediate # from operand
      struct parsed_num_t *parsed_num = parse_num(asm_line->operand3);
      int16_t immediate = parsed_num->num;
      free(parsed_num);
      // printf("immediate: %d\n", immediate);
      if (asm_line->opcode[2] == 'w' && (immediate & 1)) {
        printf("invalid immediate: %d\n", immediate);
        parsed_asm->valid_asm = false;
        parsed_asm->error_code = 3;
        return parsed_asm;
      }

      // Check if immediate is between valid min/max
      if (immediate < min || immediate > max) {
        parsed_asm->valid_asm = false;
        parsed_asm->error_code = 3;
        return parsed_asm;
      }
      uint16_t unsigned_immediate = immediate;
      if (immediate < 0) {
        unsigned_immediate <<= shift_bits;
        unsigned_immediate >>= shift_bits;
      }
      parsed_asm->machine_code |= unsigned_immediate;
      break;
    }

    // lea has no shared mapping
    case 8: {
      break;
    }
    
    // nop and rti have same mapping
    case 9:
    case 15: {
      break;
    }
    
    // not has no shared mapping
    case 10: {
      uint16_t dr = parse_register(asm_line->operand1) << 9;
      uint16_t base = parse_register(asm_line->operand2) << 6;
      printf("dr: %d\nbase: %d\n", dr, base);
      parsed_asm->machine_code |= (dr | base | 0x3F);
      break;
    }

    // ret has no shared mapping
    case 11: {
      break;
      parsed_asm->machine_code |= (0x1B0);
    }

    // lshf, rsfl, rshfa have same mapping
    case 12:
    case 13:
    case 14: {
      uint16_t dr = parse_register(asm_line->operand1) << 9;
      uint16_t base = parse_register(asm_line->operand2) << 6;
      printf("dr: %d\nbase: %d\n", dr, base);
      parsed_asm->machine_code |= (dr | base);
      if (asm_line->opcode[0] == 'r'){
        if (asm_line->opcode[4] == 'l') {
          parsed_asm->machine_code |= 0x10;
        } else {
          parsed_asm->machine_code |= 0x30;
        }
      }

      // Parse immediate # from operand
      struct parsed_num_t *parsed_num = parse_num(asm_line->operand3);
      int16_t immediate = parsed_num->num;
      free(parsed_num);

      // Check if immediate is between valid min/max
      if (immediate < min || immediate > max) {
        parsed_asm->valid_asm = false;
        parsed_asm->error_code = 3;
        return parsed_asm;
      }

      // Shouldn't need to shift because it is unsigned
      // uint16_t shift_amount = immediate;
      // if (immediate < 0) {
      //   int shift_bits = 16 - immediate_bits[opcode_number];
      //   shift_amount <<= shift_bits;
      //   shift_amount >>= shift_bits;
      // }

      parsed_asm->machine_code |= immediate;
      break;
    }

    // trap has no shared mapping
    case 18: {
      // Parse immediate # from operand
      struct parsed_num_t *parsed_num = parse_num(asm_line->operand3);
      int16_t immediate = parsed_num->num;
      free(parsed_num);

      // Check if immediate is between valid min/max
      if (immediate < min || immediate > max) {
        parsed_asm->valid_asm = false;
        parsed_asm->error_code = 3;
        return parsed_asm;
      }

      uint16_t trap_vector = immediate;
      if (immediate < 0) {
        trap_vector <<= shift_bits;
        trap_vector >>= shift_bits;
      }

      parsed_asm->machine_code |= trap_vector;
      break;
    }

    // halt, in, out, getc, puts have same mapping
    case 20:
    case 21:
    case 22:
    case 23:
    case 24: {
      parsed_asm->machine_code |= 0x25;
      break;
    }

    // fill has no shared mapping
    case 42: {
      break;
    }
  }

  return parsed_asm;
}

int main_tester(int argc, char* argv[]) {
  char buffer[MAX_LINE_LENGTH];
  fgets(buffer, MAX_LINE_LENGTH, stdin);
  buffer[strcspn(buffer, "\n")] = 0;
  // struct parsed_num_t *parsed_num = parse_num(buffer);
  // printf("valid: %d\nnum: %d", parsed_num->valid_num, parsed_num->num);
  struct asm_line_t *asm_line = tokenize_line(buffer);
  printf("state: %d\nvalid: %d\nlabel: %s\nopcode: %s\nop1: %s\nop2: %s\nop3: %s\n", asm_line->state, asm_line->valid_line, asm_line->label_name, asm_line->opcode, asm_line->operand1, asm_line->operand2, asm_line->operand3);
  validate_asm_line(asm_line);
  free_asm_line(asm_line);
  return 0;
}

int main(int argc, char* argv[]) {
  // Print usage if wrong number of args
  if (argc != 3) {
    printf("Usage: %s <asm file in> <obj file out>\n", argv[0]);
    return 1;
  }

  // Open asm file to read from
  FILE *asm_file = fopen(argv[1], "r");
  if (!asm_file) {
    printf("Error: Cannot open file %s\n", argv[1]);
    exit(4);
    return 1;
  }

  // Open obj file to write to
  FILE *obj_file = fopen(argv[2], "w");
  if (!obj_file) {
    printf("Error: Cannot open file %s\n", argv[2]);
    exit(4);
    return 1;
  }

  // Initialize assembler state
  asm_state.state = INITIAL;
  for (int i = 0; i < MAX_SYMBOLS; i++)
    asm_state.sym_table[i] = NULL;
  asm_state.num_labels = 0;
  asm_state.cur_address = 0;
  asm_state.orig_address = 0;

  // Buffer for reading input from asm file
  char buffer[MAX_LINE_LENGTH];
  
  // Keep track of line # in asm file
  int line_number = 1;

  // Loop through asm file to find labels
  while (fgets(buffer, MAX_LINE_LENGTH, asm_file) != NULL) {
    // Convert buffer to all lowercase
    for (int i = 0; i < MAX_LINE_LENGTH && buffer[i] != '\0'; i++) {
      buffer[i] = tolower(buffer[i]);
    }

    // Tokenize asm string
    struct asm_line_t *asm_line = tokenize_line(buffer);
    // printf("state: %d\nvalid: %d\nlabel: %s\nopcode: %s\nop1: %s\nop2: %s\nop3: %s\n", asm_line->state, asm_line->valid_line, asm_line->label_name, asm_line->opcode, asm_line->operand1, asm_line->operand2, asm_line->operand3);
    
    // Checks for empty line and skips it
    if (asm_line->state == EMPTY_LINE || asm_state.state == END) {
      line_number++;
      free_asm_line(asm_line);
      continue;
    }

    // Make sure the line is valid
    if (!asm_line->valid_line || !validate_asm_line(asm_line)) {
      printf("Line %d is invalid", line_number);
      free_asm_line(asm_line);
      exit(2);
      return 1;
    }

    // Check for .orig
    if (asm_state.state == INITIAL) {
      if (strcmp(asm_line->opcode, ".orig") == 0) {
        struct parsed_num_t *parsed_num = parse_num(asm_line->operand1);

        // Check if odd address
        if (parsed_num->num & 1) {
          printf("Address provided to .ORIG is odd\n");
          free(parsed_num);
          exit(3);
          return 1;
        }

        // Store as orig address
        asm_state.orig_address = parsed_num->num;
        asm_state.state = ORIG_SET;
        asm_state.cur_address = parsed_num->num;
        free(parsed_num);
      } else {
        printf("Expected .ORIG as first instruction\n");
        exit(4);
        return 1;
      }
    } else if (asm_line->label_name != NULL) {
      // Create a new label and set its address and copy its name
      struct label_t *new_label = (struct label_t *) malloc(sizeof(struct label_t));
      new_label->address = asm_state.cur_address;
      strcpy(new_label->name, asm_line->label_name);

      // Add to symbol table of assembler
      asm_state.sym_table[asm_state.num_labels++] = new_label;
    } else if (strcmp(asm_line->opcode, ".end") == 0) {
      asm_state.state = END;
    }

    free_asm_line(asm_line);
    line_number++;
    asm_state.cur_address += 2;
  }

  // Debug print for symbol table
  for (int i = 0; i < MAX_SYMBOLS; i++) {
    if (asm_state.sym_table[i] != NULL) {
      struct label_t *label = asm_state.sym_table[i];
      printf("label name: %s\nlabel addr: %X\n", label->name, label->address);
    }
  }
  
  // Rewind file to beginning to start writing to obj code
  rewind(asm_file);

  // Reset asm state
  asm_state.state = INITIAL;
  asm_state.cur_address = asm_state.orig_address;
  line_number = 1;
  while(fgets(buffer, MAX_LINE_LENGTH, asm_file) != NULL) {
    // Convert buffer to all lowercase
    for (int i = 0; i < MAX_LINE_LENGTH && buffer[i] != '\0'; i++) {
      buffer[i] = tolower(buffer[i]);
    }

    // Tokenize asm string
    struct asm_line_t *asm_line = tokenize_line(buffer);

    // Check if we skip the current line (ie: if there was only a comment)
    if (asm_line->state == EMPTY_LINE) {
      line_number++;
      free_asm_line(asm_line);
      continue;
    }
  
    // Get line from parsed asm
    struct parsed_asm_t *line = parse_asm(asm_line);

    // Check for error in parsing asm
    if (!line->valid_asm) {
      printf("Error in line %d\n", line_number);
      exit(line->error_code);
      return 1;
    }

    // Check if we skip the current line (ie: if there was only a comment)
    if (asm_line->state == EMPTY_LINE) {
      line_number++;
      free_asm_line(asm_line);
      free(line);
      continue;
    }

    // Format machine code to hex string and print to obj file
    fprintf(obj_file, "0x%04X\n", line->machine_code); 

    // Free structs
    free_asm_line(asm_line);
    free(line);
    asm_state.cur_address += 2;
    line_number++;
  }

  // Close file to flush buffer and write to disk
  fclose(asm_file);
  fclose(obj_file);
  return 0;
}

