#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <gelf.h>
//% #include <sys/auxv.h>
#include <sys/types.h>
#include <sys/mman.h>

extern char** environ;

int main(int argc, char * argv[]) 
{
	int fd;
	Elf * e;	
	size_t n, shstrndx, sz, page_size;	
	int i;
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
	/*/ set up the stack
	// first get the stack pointer
	asm("movq rsp , rax \n\t");
	register long stack_loc asm("rax");
	char * addr = stack_loc;
	addr = addr - 8;
	*addr = 'h';
	addr = addr - 8;
	*addr = 'e';
	printf("The stack address is: %lx\n", stack_loc);
	*/
	char c = 'h';
	char d = 'e';
    	//int m = 100;
	asm volatile(
	"push %%ax\n\t"
	"push %%bx\n\t"
        : 
	:"a"(c), "b"(d)
	:);

	elf_end(e);
	close(fd);
	return 0;
	
}
