/**
 * @brief test program that generates BPF PC relative call instructions
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

extern void log_64(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__ ((noinline)) log_wrapper(uint64_t x) {
  log_64(0, 0, 0, 0, x);
  return x;
}

uint64_t __attribute__ ((noinline)) syscall(uint64_t x) {
  uint64_t y = 100;
  uint64_t z = 10;
  x += log_wrapper(x);
  x += log_wrapper(y);
  x += log_wrapper(z);
  return x;
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t x = (uint64_t)*input;
  x = syscall(x);
  return x;
}

