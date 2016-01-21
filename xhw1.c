#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include "sheader.h"
#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif


/* Function to generate key from the passphrase entered by the user */
unsigned char * md5_key_generate(char * a, int len)
{

	MD5_CTX c;
	unsigned char *digest=(unsigned char*)malloc(16);
	MD5_Init(&c);
	while(len>0){
		if(len>512){
			MD5_Update(&c,a,512);
		}
		else{
			MD5_Update(&c,a,len);
	
		}
	len-=512;
	a+=512;
	}

	MD5_Final(digest,&c);
	
	return digest;
}

/* Main function in userspace which invokes the sys_xcrypt syscall*/
int main(int argc, char *argv[])
{
	int rc,i,j;
	int edflag=0;
	int pflag=0;
	int option;
	int err=0;
	int err1=0;
	char *key;
	extern char *optarg;
	extern int optind;
        struct fval f1;

	/* Parsing options using the getopt() function. Checks for all bad inputs */
	while((option=getopt(argc,argv,"edp:h"))!=-1){
		switch(option){
			case 'e':
				if(edflag==1){
					printf("WARNING! encryption/decryption flag is set multiple number of times\n");
				}
				edflag=1;
				f1.flag=0;
				break;
			case 'd':
				if(edflag==1){
					printf("WARNING! encryption/decrption flag is set multiple number of times\n");
				}
				edflag=1;
				f1.flag=1;
				break;
			case 'p':
				if(pflag==1){
					printf("WARNING! password flag is set multiple number of times\n");
				}
				pflag=1;
				
				i=0;
				j=0;
				while(optarg[i]){
				if(optarg[i]!='\n'){
					key[j]=optarg[i];
					j++;
				}
				i++;
				}
				key[j]='\0';
				break;
			case 'h':
				printf("**********This is an encryption decryption syscall module************\n");
				printf("Enter -e to encrypt the file or -d to decrypt the file\n");
				printf("Enter -p option along with the password you want to set\n");
				printf("Enter input and output filenames\n");
				err1=1;
				break;
			case '?':
				err=1;
				break;
			default:
				printf("Enter -e to encrypte or -d to decrypt the file along with input and output filenames\n");
				break;
		}
	}
	/* checks if any invalid option is entered */
	if(err==1){
                printf("Invalid option entered\n");
                exit(1);
	}
	/* checks if user has entered -h option */
	else if(err1==1){
		exit(1);
	}
	/* checks if passphrase has been entered by the user along with -p option */
	else if(edflag==0&&pflag==1){
                printf("-p requires an argument\n");
		exit(1);
        
	}
	/* checks if -e/-d and -p options have been specified by the user */
	else if(edflag==0||pflag==0){
		printf("INVALID OPTIONS!!!..PLEASE SELECT OPTIONS AS FOLLOWS\n");
		printf("Please enter -e for encryption or -d for decryption\n");
		printf("Enter -p along with password\n");
		exit(1);
	}
	/* checks if user has entered both the input file and output file */
	else if((optind+2)>argc){
		printf("Missing Arguments: FileNames\n");
		exit(1);
	}
	/*checks for the length of the password */
	else if(strlen(key)<6){
		printf("Password too small!!\n");
		exit(1);
	}
	
	if(optind<argc){
		f1.infile=argv[optind];
		optind++;
		f1.outfile=argv[optind];
	}

	/* calls md5_key_generate to generate a key for md5 hashing at user level */	
	f1.keybuf=md5_key_generate(key,strlen(key));	
	
	void *dummy = (void *)&f1;

	/*invoking system call */
  	rc = syscall(__NR_xcrypt, dummy);


	if (rc == 0)
		printf("\nsyscall returned %d\n", rc);
	else{
		printf("syscall returned %d (errno=%d)\n", rc, errno);
		perror("ERROR IN SYSCALL: ");
	}

	exit(rc);
	
	
}
