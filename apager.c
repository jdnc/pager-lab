#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <gelf.h>
#include <sys/mman.h>
#define MAXBUF 

int main(int argc, char * argv[]) 
{
	int fd;
	Elf * e;	
	size_t n, shstrndx, sz;	
	int i;
	Elf_Scn * scn;
	Elf_Data * data;
	void * loc;
	GElf_Shdr shdr;
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
	while((scn = elf_nextscn(e, scn)) != NULL) {
		if(gelf_getshdr(scn, &shdr) == NULL){
			perror("getshdr failed");
			exit(1);
		}
		if (shdr.sh_type == SHT_PROGBITS) {
			if ((loc = mmap((void *)shdr.sh_addr, (size_t)shdr.sh_size, 
			PROT_EXEC | PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, (off_t)shdr.sh_offset)) == MAP_FAILED) {
				perror("could not mmap the region");
			}
			if (! (shdr.sh_flags & SHF_WRITE)) {
				if (mprotect((void*)shdr.sh_addr, (size_t)shdr.sh_size, PROT_READ) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}
			if (shdr.sh_flags & SHF_EXECINSTR) {
				if (mprotect((void*)shdr.sh_addr, (size_t)shdr.sh_size, PROT_EXEC) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}	
		}
		else if (shdr.sh_type == SHT_NOBITS) {
			if ((loc = mmap((void *)shdr.sh_addr, (size_t)shdr.sh_size, PROT_READ | PROT_WRITE, 
			     MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
				perror("could not mmap the region");
			}
			if (! (shdr.sh_flags & SHF_WRITE)) {
				if (mprotect((void*)shdr.sh_addr, (size_t)shdr.sh_size, PROT_READ) < 0) {
					perror("mprotect failed");
					exit(1);
				}
			}
			
		}
	}
	elf_end(e);
	close(fd);
	return 0;
}
