/* dash_shell_test.c */ 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main() {
	char *argv[2];
	argv[0] = "/bin/sh";
	argv[1] = NULL;
	// setuid(0); //important part.
	execve("/bin/sh", argv, NULL); return 0;}