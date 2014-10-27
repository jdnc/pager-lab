#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gelf.h>
#include <sys/types.h>
#include <sys/mman.h>

// IMPORTANT NOTE: The following 2 macros were taken from an online source
#define ALIGN(k,v) (((k)+((v)-1))&(~((v)-1)))
#define ROUNDUP(x, y) ((((x)+((y)-1))/(y))*(y))

extern char** environ;

int main(int argc, char * argv[]) 
{
	int fd;
	Elf * e;	
	size_t n, shstrndx, sz, page_size;	
	int i, j;
	Elf_Scn * scn;
	Elf_Data * data;
	void * loc;
	void * prevAddr = 0;
	GElf_Shdr shdr;
	page_size = getpagesize();
	// first of all open and check the binary
	if ((fd = open(argv[1], O_RDONLY, 0)) < 0) {
		perror("could not open executable");
		exit(fd);
	}
	
	// locate the different sections and sizes from the program header
	GElf_Phdr phdr;
	if (elf_version(EV_CURRENT) == EV_NONE) {
		perror("Elf lib init failed");
		exit(1);
	}
	if ((e = elf_begin(fd, ELF_C_READ, NULL)) == NULL ) {
		perror("elf_begin failed");
		exit(1);
	}	
	if (elf_kind(e) != ELF_K_ELF) {
		perror("not an elf object");
		exit(1);
	}
/*	if (elf_getphdrnum(e, &n) != 0) {	
	perror("could not get phdrnum");
		exit(1);
	}	

	int count = 0;
	for(i=0; i < n ; ++i) {
		void * loc = NULL;
		if (gelf_getphdr(e, i, &phdr) == NULL) {
			perror("elf_gethdr failed");
			exit(1);
		}
		if (phdr.p_type != PT_LOAD)
			continue;
		count++;
		
		
	}
	printf("number of load sections is %d\n.", count);
*/
	if (elf_getshdrstrndx(e, &shstrndx) != 0) {
		perror("elf_getshdrstrndx failed");
		exit(1);
	}
	scn = NULL;
	int count = 0;
	while((scn = elf_nextscn(e, scn)) != NULL) {
		if(gelf_getshdr(scn, &shdr) == NULL){
			perror("getshdr failed");
			exit(1);
		}
		void * addr = (void *)(shdr.sh_addr - shdr.sh_addr % page_size);
		off_t off = (off_t)(shdr.sh_offset - shdr.sh_offset % page_size);
		// if first time, check whether the program is loading on top of itself
		if (count == 0) {
			msync(addr, page_size, MS_SYNC);
			if (errno != ENOMEM) {
			  fprintf(stderr, "address is already mapped\n");
			  exit(1);
			}
		}		
		++count;
		if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_ALLOC)) {
		//	mmap(NULL, 4096, PROT_READ|PROT_WRITE,
		//	MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
		//	perror("mmap :" );
			if ((loc = mmap(addr, shdr.sh_size, 
			PROT_EXEC | PROT_READ,  MAP_PRIVATE | MAP_FIXED, fd, off)) == MAP_FAILED) {
				perror("could not mmap the region");
				exit(1);
			}
			if (shdr.sh_flags & SHF_WRITE) {
				if (mprotect(addr, (size_t)shdr.sh_size, PROT_WRITE) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}
			if (shdr.sh_flags & SHF_EXECINSTR) {
				if (mprotect(addr, (size_t)shdr.sh_size, PROT_EXEC) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}	
			prevAddr = addr;
		}
		else if (shdr.sh_type == SHT_NOBITS && (shdr.sh_flags & SHF_ALLOC)) {
			if (! (addr == prevAddr)) {
				if ((loc = mmap(addr, (size_t)shdr.sh_size, PROT_READ | PROT_WRITE, 
				    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0)) == MAP_FAILED) {
					perror("could not mmap the region");
					exit(1);
				}
				prevAddr = addr;
			}
//			memset((void *)shdr.sh_addr, 0x0, (size_t)shdr.sh_size);
			if (!(shdr.sh_flags & SHF_EXECINSTR)) {
				if (mprotect(addr, (size_t)shdr.sh_size, PROT_READ) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}
			if (shdr.sh_flags & SHF_WRITE) {
				if (mprotect(addr, (size_t)shdr.sh_size, PROT_WRITE) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}
			
		}
	}

	// now get the entry point of the program and write some assembly
	GElf_Ehdr ehdr;
	if(gelf_getehdr(e, &ehdr) == NULL) {
		perror("getehdr error.");
		exit(1);
	}
	printf("The entry point of the program is: %x\n", ehdr.e_entry);
//	set up the stack
//	 first get the stack pointer
//	asm("movq rsp , rax \n\t");
//	register long stack_loc asm("rax");
//	char * addr = stack_loc;
//	addr = addr - 8;
//	*addr = 'h';
//	addr = addr - 8;
//	*addr = 'e';
//	printf("The stack address is: %lx\n", stack_loc);
//	char c = 'h';
//	char d = 'e';
//    	//int m = 100;
//	asm volatile(
//	"push %%ax\n\t"
//	"push %%bx\n\t"
//        : 
//	:"a"(c), "b"(d)
//	:);

	// now set up the stack
	char *child_stack = malloc(sizeof(char) * 16384);
	unsigned long * ptr;
	char **aloc, **eloc;
	//ptr = (unsigned long *) child_stack;
	char * rsp = (char *)ALIGN(((unsigned long)child_stack), 16);
	ptr = (unsigned long*) rsp;
	// since stack grows down, we will set this up in reverse order
	// insert argc
	*ptr++ = argc - 1;
	aloc = (char**)ptr;
	// fill in argv address later
	ptr += (argc - 1);
	*ptr++ = 0;
	eloc = (char **)ptr;
	// fill in envp later
	char** aux_loc = environ;
	for (i = 0; environ[i] != NULL; ++i);
	aux_loc = &environ[i];
	aux_loc++;
	*ptr++ = 0;
	// now fill in auxilliary vectors
	// fill them in from the parent program, change the differences
	Elf64_auxv_t *aux, *exfn;
	
	// TODO : shouldn't aux_loc be one more?
	// go to the start 
	Elf64_auxv_t* aux_copy = (Elf64_auxv_t*) ptr;
	for(aux = (Elf64_auxv_t *)aux_loc, count = 0; aux->a_type != AT_NULL; aux++, count++)
	
        {
	//	memcpy((void *)ptr, (void *)aux, sizeof(Elf64_auxv_t));
		aux_copy[count].a_type = aux->a_type;
		aux_copy[count].a_un.a_val = aux->a_un.a_val;
		switch(aux->a_type)
		{
		 case AT_PHDR:
			aux[count].a_un.a_val = (unsigned long)((char*) (&ehdr) + ehdr.e_phoff); break;
		 case AT_PHNUM:
			aux[count].a_un.a_val = ehdr.e_phnum; break;
		 case AT_PHENT:
			aux[count].a_un.a_val = ehdr.e_phentsize; break;
		 case AT_ENTRY:
			aux[count].a_un.a_val = ehdr.e_entry; break;
		 case AT_EXECFN:
			exfn = (Elf64_auxv_t *)ptr; break;
		}
		ptr += 2;
	}
	*ptr++ = 0;
	char * tmp = (char *) ptr;
	// now enter argv strings
	for (i = 1; i < argc; ++i) {
	  aloc[i-1] = tmp;
	  for (j = 0; argv[i][j] != NULL; ++j){
		*tmp++ = argv[i][j];
	  }
	  *tmp++ = '\0';
	}
	ptr = (unsigned long *)(tmp);
	*ptr++ = 0;
	tmp = (char *)ptr;
	// now enter the envp strings
	for(i = 0; environ[i] != NULL; ++i){
		eloc[i] = tmp;
		for (j=0; environ[i][j] != NULL; ++j) {
			*tmp++ = environ[i][j];
		}
		*tmp++ = '\0';
	}
	ptr = (unsigned long *) tmp;
//	*ptr++ = 0;
	tmp = (char *) ptr;
	// finally the name of the executable
	exfn->a_un.a_val = (unsigned long)tmp;
	for(i = 0; argv[1][i] != NULL; ++i)
		*tmp++ = argv[1][i];
	*tmp++ = '\0';
	ptr = (unsigned long *) tmp;
	asm volatile("movq %0, %%rsp\n\t"::"r"((void *) rsp));
	asm volatile("xor %%rdx, %%rdx\n\t"::);
	asm volatile("xor %%eax, %%eax\n\t"::);
	asm volatile("xor %%ebx, %%ebx\n\t"::);
	asm volatile("jmp *%0\n\t"::"r"((void *) ehdr.e_entry));
	elf_end(e);
	close(fd);
	return 0;
	

}
