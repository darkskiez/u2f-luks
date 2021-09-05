package main

// #include <libcryptsetup.h>
// void golog(int level, char *msg);
// extern void logcb(int level, const char *msg, void *usrptr) {
//   golog(level, msg);
// }
// void setuplogcb() {
//	crypt_set_log_callback(NULL, &logcb, NULL);
// }
import "C"
