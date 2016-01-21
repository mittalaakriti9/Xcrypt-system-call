obj-m += sys_xcrypt.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xcipher xcrypt

xcipher: xhw1.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xhw1.c -o xcipher -lcrypto -lssl 

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcipher
