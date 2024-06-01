#pragma once
/**
 * @brief Solana logging utilities
 */

#include <sor/types.h>
#include <sor/string.h>
#include <sor/entrypoint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Prints a string to stdout
 */
void sol_log_(const char *, uint64_t);
#define sor_log(message) sol_log_(message, sor_strlen(message))

/**
 * Prints a 64 bit values represented in hexadecimal to stdout
 */
void sol_log_64_(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
#define sor_log_64 sol_log_64_

/**
 * Prints the current compute unit consumption to stdout
 */
void sol_log_compute_units_();
#define sor_log_compute_units() sol_log_compute_units_()

/**
 * Prints the hexadecimal representation of an array
 *
 * @param array The array to print
 */
static void sor_log_array(const uint8_t *array, int len) {
  for (int j = 0; j < len; j++) {
    sor_log_64(0, 0, 0, j, array[j]);
  }
}

/**
 * Print the base64 representation of some arrays.
 */
void sol_log_data(SolBytes *fields, uint64_t fields_len);

/**
 * Prints the program's input parameters
 *
 * @param params Pointer to a SolParameters structure
 */
static void sor_log_params(const SolParameters *params) {
  sor_log("- Program identifier:");
  sol_log_pubkey(params->program_id);

  sor_log("- Number of KeyedAccounts");
  sor_log_64(0, 0, 0, 0, params->ka_num);
  for (int i = 0; i < params->ka_num; i++) {
    sor_log("  - Is signer");
    sor_log_64(0, 0, 0, 0, params->ka[i].is_signer);
    sor_log("  - Is writable");
    sor_log_64(0, 0, 0, 0, params->ka[i].is_writable);
    sor_log("  - Key");
    sol_log_pubkey(params->ka[i].key);
    sor_log("  - Lamports");
    sor_log_64(0, 0, 0, 0, *params->ka[i].lamports);
    sor_log("  - data");
    sor_log_array(params->ka[i].data, params->ka[i].data_len);
    sor_log("  - Owner");
    sol_log_pubkey(params->ka[i].owner);
    sor_log("  - Executable");
    sor_log_64(0, 0, 0, 0, params->ka[i].executable);
    sor_log("  - Rent Epoch");
    sor_log_64(0, 0, 0, 0, params->ka[i].rent_epoch);
  }
  sor_log("- Instruction data\0");
  sor_log_array(params->data, params->data_len);
}

#ifdef sor_TEST
/**
 * Stub functions when building tests
 */
#include <stdio.h>

void sol_log_(const char *s, uint64_t len) {
  printf("Program log: %s\n", s);
}
void sor_log_64(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  printf("Program log: %llu, %llu, %llu, %llu, %llu\n", arg1, arg2, arg3, arg4, arg5);
}

void sol_log_compute_units_() {
  printf("Program consumption: __ units remaining\n");
}
#endif

#ifdef __cplusplus
}
#endif

/**@}*/
