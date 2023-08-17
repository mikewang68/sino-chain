/**
 * @brief test program used to test unresolved syscall handling
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log(const char*, uint64_t);
extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

extern uint64_t entrypoint(const uint8_t *input) {
  log(__func__, sizeof(__func__));
  log_64(1, 2, 3, 4, 5);
  return 0;
}
