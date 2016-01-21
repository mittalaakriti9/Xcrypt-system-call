/*
 * Author: Aakriti Mittal
 * Email : aamittal@cs.stonybrook.edu
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under terms of GNU General Public License Verification
 * 2 as published by the free software foundation.

 * sys_xcrypt.c- kernel module which performs the encryption and decryprion 
 * files by calling sys_xcrypt() system call.
 */ 

#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include "sheader.h"
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/dcache.h>

asmlinkage extern long (*sysptr)(void *arg);

/* List of functions defined in the program */
struct filename *ret_ker_add(const char *a);
static int add_preamble(struct file *out_f,unsigned char *i);
static int check_preamble(struct file *in,unsigned char *i);
unsigned char *key_encrypt(unsigned char *key);
static int func_read_write(struct filename *in,struct filename *out,unsigned char *key,int flag);
static int func_encrypt_decrypt(char *buf,unsigned char *key,int flag);
static int check_files(struct file *in_f,struct file *out_f);
static int unlink_file(struct file *target);


/* ret_ker_add takes user argument and returns a kernel address 
 * by calling getname function.
 */
struct filename * ret_ker_add(const char * a)
{
	struct filename *temp;
	temp=getname(a);
	return temp;
	
}



/* unlink_file()function unlinks a targat file by calling
 * vfs_unlink syscall.
 */ 
static int unlink_file(struct file *target)
{
	
	int rc;
	struct inode *i=(target->f_path.dentry->d_parent->d_inode);
	struct dentry *d=(target->f_path.dentry);
	struct dentry *d1=NULL;

	dget(d);
	d1=dget_parent(d);
	
	mutex_lock_nested(&(d1->d_inode->i_mutex), I_MUTEX_PARENT);
	rc=vfs_unlink(i,d,0);
	if(rc){
		printk(KERN_ERR "Error in vfs_unlink; rc = [%d]\n", rc);
                goto out_unlock;
	}
	

out_unlock:

	mutex_unlock(&d1->d_inode->i_mutex);
        dput(d);
	return rc;

}


/* rename_files() renames the source file with the target file
 * by using vfs_rename() syscall.
 */
static int rename_files(struct file *f_tmp,struct file *f_out)
{
	int rc;
	struct dentry *trap=NULL;
	struct dentry *d1=NULL;
	struct dentry *d2=NULL;
	struct inode *old_dir=(f_tmp->f_path.dentry->d_parent->d_inode);
	struct dentry *old_dentry=(f_tmp->f_path.dentry);
	struct inode *new_dir=(f_out->f_path.dentry->d_parent->d_inode);
	struct dentry *new_dentry=(f_out->f_path.dentry);
	
	dget(old_dentry);
	dget(new_dentry);

	d1=dget_parent(old_dentry);
	d2=dget_parent(new_dentry);

	trap=lock_rename(d1,d2);
	if(trap==old_dentry){
		rc=-EINVAL;
		goto out_lock;
	}

	if(trap==new_dentry){
		rc=-ENOTEMPTY;
		goto out_lock;
	}

	rc=vfs_rename(old_dir,old_dentry,new_dir,new_dentry,NULL,0);
	if (rc){
                 goto out_lock;
	}


out_lock:

	unlock_rename(d1,d2);
	dput(d1);
	dput(d2);
	dput(old_dentry);
	dput(new_dentry);
	return rc;

}
/* check_files() is used to check the input and output files
 * for regularity, symlinks and deirectories. Returns -1 if 
 * error conditions exist
 */	
static int check_files(struct file *in_f,struct file *out_f)
{

	if(in_f->f_path.dentry->d_inode==NULL){
		printk("The source file does not exist\n");
		return -1;
	}
	else if(in_f->f_path.dentry->d_inode==out_f->f_path.dentry->d_inode){
		printk("Input and output files are the same\n");
		return -1;
	}
	else if(!S_ISREG(in_f->f_inode->i_mode)||!S_ISREG(out_f->f_inode->i_mode)){
		printk("Input or Output file is not a regular file\n");
		return -1;
	}

	return 0;

}


/* add_preamble() adds the hashed key to the preamble of the
 * output file.
 */
static int add_preamble(struct file *out_f,unsigned char *i)
{
	if(i==NULL){
		printk("ERROR GENERATING THE HASH VALUE OF THE KEY FOR THE Preamble\n");
		return 0;
	}
	else{
		out_f->f_op->write(out_f,i,16,&out_f->f_pos);
		printk("Sucessfully added preamble\n");
		return 1;
	}

	

}

/*This checks if the key given by the user to decrypt the file
 *is same as the one which is appended in the preamble
 */
static int check_preamble(struct file *in,unsigned char *i)
{

	char *cbuf=kmalloc(16,GFP_KERNEL);
	if(i==NULL){
		printk("ERROR GENERATING THE HASH VALUE OF THE KEY FOR THE PREAMBLE\n");
		return 0;
	}
	else{
		in->f_op->read(in,cbuf,16,&in->f_pos);
		if(!(memcmp(i,cbuf,16))){
			printk("Key Matched Succesfully\n");
			return 1;
		}
		else{
			printk("Key Matching Failed: Aborting Decryption\n");
			kfree(cbuf);
			return 0;
		}


	}

}


/* key_encrypt() encrypts the key coming from user level
 * to get appended in the preamble part of output file.
 * This uses md5 hashing technique.Returns the value of the 
 * hashed key.
 */

unsigned char *key_encrypt(unsigned char *key)
{
	
	struct scatterlist sg;
	struct crypto_hash *tfm;
	struct hash_desc desc;
  	unsigned char * output;
	int err;
	output=kmalloc(sizeof(*output)*16, GFP_KERNEL);
	memset(output, 0x00, 16);
	tfm = crypto_alloc_hash("md5", 0,0);
	if(IS_ERR(tfm)){
		printk("could not allocate handle for hash function \n");
                err=PTR_ERR(tfm);
		return NULL;
	}
	desc.tfm = tfm;

  	desc.flags = 0;
	sg_init_one(&sg, key, 16);
  	crypto_hash_init(&desc);
	crypto_hash_update(&desc, &sg, 16);
  	crypto_hash_final(&desc, output);
	if(tfm)
		crypto_free_hash(tfm);


	return output;

}

/*
 * func_encrypt_decrypt performs encryption and decryption functionality using 
 * the crypto API in Linux Kernel.The technique used is aes encryption 
 * in ctr mode.It is called from func_read_write. It takes read buffer, hashed key 
 * and encryption/decryption flag as inputs. 
 */
static int func_encrypt_decrypt(char *buf,unsigned char *key,int flag)
{
        struct crypto_blkcipher *blkcipher=NULL;
        char *cipher="ctr(aes)";
        int ret=-EFAULT;
        struct scatterlist sg;
        struct blkcipher_desc desc;
	

        blkcipher=crypto_alloc_blkcipher(cipher,0,0);
        if (IS_ERR(blkcipher)) {
                printk("could not allocate blkcipher handle for %s\n", cipher);
                return -PTR_ERR(blkcipher);
        }
        if (crypto_blkcipher_setkey(blkcipher, key, 16)) {
                printk("key could not be set\n");
                ret = -EAGAIN;
                goto out;
        }

	crypto_blkcipher_set_iv(blkcipher, key, 16);

	desc.flags = 0;
	desc.tfm = blkcipher;
	sg_init_one(&sg,buf,PAGE_SIZE);

	if(flag==0)
		crypto_blkcipher_encrypt(&desc,&sg,&sg,PAGE_SIZE);

	if(flag==1)
		crypto_blkcipher_decrypt(&desc,&sg,&sg,PAGE_SIZE);


	ret = 1;
out:
	if (blkcipher)
		crypto_free_blkcipher(blkcipher);

	return ret;
}

/* 
 * func_read_write performs all functionalities related to reading and writing files
 * Opens input and output files and creates a temporary file. Checks for all the 
 * valid conditions for files;returns relevant errors
 * Writes encrypted or decrypted data to a temporary file depending upon the value of flag 
 * Incase of partial failure, it unlinks the temporary file; otherwise, it renames the temporary 
 * file as the output file.
 */
static int func_read_write(struct filename *in,struct filename *out,unsigned char *key,int flag)
{

	struct file *in_f,*out_f=NULL,*temp=NULL;
	mm_segment_t ofs;
	int ret,err;
	int enc;
	char *buf;
	unsigned char * i;
	int a,b;
	int w_ret;
	int check;
	int out_flag,in_flag;
	int wflag=0;
	struct kstat stat;

	i=kmalloc(sizeof(*i)*16, GFP_KERNEL);
	if(!i){
 		printk("Error Allocating Memory\n");
                return -ENOMEM;
        }
	buf=kmalloc(PAGE_SIZE,GFP_KERNEL);
	if(!buf){
        	printk("Error Allocating Memory\n");
		kfree(i);
                return -ENOMEM;
	}
	memset(buf,0,PAGE_SIZE);

	/* Opening input file for read operation*/
	in_f=filp_open(in->name,O_RDONLY,0);

	/* Checking if a file exists*/
	if(!in_f){
        	printk("File does not exist:Bad File.\n");
		err= -EBADF;
		goto out;
	}

	/*Checking error in file poniter */
	if(IS_ERR(in_f)){
		printk("Cannot Open the source file\n");
		err=PTR_ERR(in_f);
		kfree(i);
		kfree(buf);
		return err;
	}

	/*Checking if the input file can be read */
	if(!in_f->f_op->read){
		printk("Infile not File System does not allow reads.\n");
		err=-EACCES;
		goto out;
	}
	/*Checking the file read permissions for the input file */
	if (!(in_f->f_mode&FMODE_READ)){
		printk("Infile not accessible to be read.\n");
		err = -EIO;
		goto out;
	}

	ofs=get_fs();
        set_fs(get_ds());
	out_flag=vfs_stat(out->name,&stat);
	in_flag=vfs_stat(in->name,&stat);
	set_fs(ofs); 

	/* Opening output file for writing */
       	out_f=filp_open(out->name,O_WRONLY|O_CREAT,stat.mode);

	/* Checking if the file exists*/
        if(!out_f){
                printk("File does not exist:Bad File.\n");
                err= -EBADF;
                goto out;
        }

        /*Checking error in file poniter */
        if(IS_ERR(out_f)){
                printk("Cannot Open the source file\n");
                err=PTR_ERR(out_f);
                kfree(i);
                kfree(buf);
                return err;
        }
	/* Checking the file write permissions of Output file */
	if (!(out_f->f_mode & FMODE_WRITE)){
	printk("Output File not accessible to be written.\n");
	err = -EIO;
	goto out;
	}
	/* Checking if Output File can be written*/
	if (!out_f->f_op->write) {
       	printk("File System does not allow writes.\n");
        err = -EACCES; 
	goto out;
	 }

 	/* To check if files are regular files, not symlinks and not directories */
	check=check_files(in_f,out_f);	
	if(check==-1){
		err=-EINVAL;
		goto out;
	}

	/* Opening temporary file for writing data */
        temp=filp_open((strcat((char *)out->name,".tmp")),O_WRONLY|O_CREAT,stat.mode);
        if(!temp){
        	printk("Unable to allocate memory to the source file\n");
                err= -ENOMEM;
		goto out;
        }

        ofs=get_fs();
        set_fs(get_ds());
	
	i=key_encrypt(key);

	if(flag==0){
		/* Adding hashed key to the output file */
		a=add_preamble(temp,i);
		if(!a){
			printk("Preamble not appended sucessfully\n");
			unlink_file(temp);
			if(out_flag!=0)
				unlink_file(out_f);
			err= -EPERM;
			goto out;
		}
	}
		
	if(flag==1){
		/* Checking The preamble for the value of the key */
		b=check_preamble(in_f,i);
		if(!b){
			printk("You are Decrypting with a wrong key\n");
			unlink_file(temp);
			if(out_flag!=0)
				unlink_file(out_f);
			err=-EPERM;
			goto out;
			
		}
		
	}
	/* Starting the read/write loop */
        do{
		ret=in_f->f_op->read(in_f,buf,PAGE_SIZE,&in_f->f_pos);
		if(ret<0){
                        printk("Read Operation Failed\n");
			set_fs(ofs);
                        unlink_file(temp);
                        if(out_flag!=0)
                                unlink_file(out_f);

			err= -EAGAIN;
			goto out;
                }

		enc=func_encrypt_decrypt(buf,key,flag);
		if(enc!=1){
                        printk("Encryption failed\n");
			set_fs(ofs);
                        unlink_file(temp);
                        if(out_flag!=0)
                                unlink_file(out_f);
                        err= -ECANCELED;
			goto out;         
	       }
		if(ret==0){
			set_fs(ofs);
			goto check;
		}

		w_ret=temp->f_op->write(temp,buf,ret,&temp->f_pos);
                if(w_ret<0){
			set_fs(ofs);
                        wflag=1;
                        break;
                }
		
	
        
        }while(1);


/* calls unlink_file() or rename_files() on the basis of success status of 
 * write opeartion and existence of output file 
 */
check:
	
        if(out_flag==0){
                if(wflag==0){
                        printk("Write Sucessful\n");
                        rename_files(temp,out_f);
                        err= 1;
			goto out;
                }
                else{
                        unlink_file(temp);
			err= -EINVAL;
			goto out;
                }
        }

        else{
                if(wflag==0){
                        printk("Write Sucessful\n");
                        rename_files(temp,out_f);
			err= 1;
			goto out;
                }

                else{
                        unlink_file(temp);
                        unlink_file(out_f);
			err= -EINVAL;
			goto out;
                }

        }

/* Cleaning Kernel resources */
out:

	 if(i)
	 	kfree(i);
	 if(buf)
     	 	kfree(buf);
	 if(in_f)
	 	filp_close(in_f,NULL);
	 if(temp)
         	filp_close(temp,NULL);
	 if(out_f)
         	filp_close(out_f,NULL);
	
	 return err;

}


iasmlinkage long xcrypt(void *arg)
{
	/* dummy syscall: returns 0 for non null, -EINVAL for NULL */
	printk("xcrypt received arg %p\n", arg);
        if (arg == NULL)
		return -EINVAL;
	else
        {
		struct fval *f; 
		struct filename *in_tmp,*out_tmp=NULL;
		unsigned char * k=NULL;
		int ret,ret1;
		int s;

		f=kmalloc(sizeof(struct fval),GFP_KERNEL);
		if(!f){
			printk("Error Allocating Memory\n");
			return -ENOMEM;
		}
		k=kmalloc(16,GFP_KERNEL);
		if(!k){
			printk("Error Allocating Memory\n");
			return -ENOMEM;
		}

		/*Copying the user space arguments to kernel space arguments*/
		ret=copy_from_user(f,arg,sizeof(struct fval));
		if(ret==0){
			in_tmp =ret_ker_add(f->infile);
			if(IS_ERR(in_tmp)){
				printk("Creation of filename input object failed\n");
				s=PTR_ERR(in_tmp);
				goto clean;
			}
			out_tmp=ret_ker_add(f->outfile);
				if(IS_ERR(out_tmp)){
					printk("Creation of filename output object failed\n");
					s=PTR_ERR(out_tmp);
					goto clean;
				
				}
			
			ret1=copy_from_user(k,f->keybuf,16);
				if(ret1!=0){
					printk("Failed to copy key\n");
					s=-ENOMEM;
					goto clean;
				
				}
		}
		else{
			printk("copy_from_user failed to allocate kernel memory\n");
			return -ENOMEM;
		
		}
		/* calling func_read_write to perform the read/write and encryption decryption process*/	
		s=func_read_write(in_tmp,out_tmp,k,f->flag);

clean:	
	if(f){
		kfree(f);
	}
	if(in_tmp){	
		putname(in_tmp);
	}
	if(out_tmp){
		putname(out_tmp);
	}
	if(k){
		kfree(k);

	}
	
		if(s==1){
			printk("System call completed successfully\n");
			return 0;
		}
		else{
			printk("Error in handling syscall\n");
			return s;
           	
	        }
	}
}


static int __init init_sys_xcrypt(void)
{
	printk("installed new sys_xcrypt module\n");
	if (sysptr == NULL)
		sysptr = xcrypt;
	return 0;
}

static void  __exit exit_sys_xcrypt(void)
{
	if (sysptr!= NULL)
		sysptr = NULL;
	printk("removed sys_xcrypt module\n");
}

module_init(init_sys_xcrypt);
module_exit(exit_sys_xcrypt);
MODULE_LICENSE("GPL");
