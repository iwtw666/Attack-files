/* stack.c */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* Suggested value: between 0 and 400 */
#ifndef BUF_SIZE 
#define BUF_SIZE 24 
#endif
// buffer overflow
int bof(char *str) {
	char buffer[BUF_SIZE];
	/* The following statement has a buffer overflow problem */
	strcpy(buffer, str);
	return 1;}
int main(int argc, char **argv) {
	char str[517];
	FILE *badfile;
	/* Change the size of the dummy array to randomize the parameters
	   for this lab. Need to use the array at least once */
	char dummy[BUF_SIZE]; memset(dummy, 0, BUF_SIZE);
	badfile = fopen("badfile", "r");
	fread(str, sizeof(char), 517, badfile);
	bof(str);
	printf("Returned Properly\n");
	return 1;}