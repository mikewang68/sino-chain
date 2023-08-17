/**
 * @brief test program that generates BPF PC relative call instructions
 */

typedef unsigned char uint8_t;
typedef unsigned long int uint64_t;

void __attribute__ ((noinline)) syscall_4(uint64_t* x) {
  *x = 42;
}

void __attribute__ ((noinline)) syscall_3(uint64_t* x) {
  uint64_t array[256];
  syscall_4(&array[128]);
  *x = array[128];
}

void __attribute__ ((noinline)) syscall_2(uint64_t* x) {
  uint64_t array[256];
  syscall_3(&array[128]);
  *x = array[128];
}

void __attribute__ ((noinline)) syscall_1(uint64_t* x) {
  uint64_t array[256];
  syscall_2(&array[128]);
  *x = array[128];
}

extern uint64_t entrypoint(const uint8_t *input) {
  uint64_t array[256];
  syscall_1(&array[128]);
  return array[128];
}

