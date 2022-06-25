#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"
#include "fs.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"
extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
	struct cpu *c;

	// Map "logical" addresses to virtual addresses using identity map.
	// Cannot share a CODE descriptor for both kernel and user
	// because it would have to have DPL_USR, but the CPU forbids
	// an interrupt from CPL=0 to DPL=3.
	c = &cpus[cpuid()];
	c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
	c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
	c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
	c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
	lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
	pde_t *pde;
	pte_t *pgtab;

	pde = &pgdir[PDX(va)];
	if(*pde & PTE_P){
		pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
	} else {
		if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
			return 0;
		// Make sure all those PTE_P bits are zero.
		memset(pgtab, 0, PGSIZE);
		// The permissions here are overly generous, but they can
		// be further restricted by the permissions in the page table
		// entries, if necessary.
		*pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
	}
	return &pgtab[PTX(va)];
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
struct shm
{
	char *name;
	int pids[50];
	struct file *f;
	char * adrese[16];
};
struct shm shared[16]; */

struct file * shared[16];
int shm_brojac=0;


struct procaddr
{
	int pid;
	int duzina;
	char * adrese[16];
	int rw;
};
char *p;
struct procaddr struktura[16];



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
	char *a, *last;
	pte_t *pte;

	a = (char*)PGROUNDDOWN((uint)va);
	last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
	for(;;){
		if((pte = walkpgdir(pgdir, a, 1)) == 0)
			return -1;
		if(*pte & PTE_P)
			panic("remap");
		*pte = pa | perm | PTE_P;
		if(a == last)
			break;
		a += PGSIZE;
		pa += PGSIZE;
	}
	return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
	void *virt;
	uint phys_start;
	uint phys_end;
	int perm;
} kmap[] = {
	{ (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
	{ (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
	{ (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
	{ (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
	pde_t *pgdir;
	struct kmap *k;

	if((pgdir = (pde_t*)kalloc()) == 0)
		return 0;
	memset(pgdir, 0, PGSIZE);
	if (P2V(PHYSTOP) > (void*)DEVSPACE)
		panic("PHYSTOP too high");
	for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
		if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
		            (uint)k->phys_start, k->perm) < 0) {
			freevm(pgdir);
			return 0;
		}
	return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
	kpgdir = setupkvm();
	switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
	lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
	if(p == 0)
		panic("switchuvm: no process");
	if(p->kstack == 0)
		panic("switchuvm: no kstack");
	if(p->pgdir == 0)
		panic("switchuvm: no pgdir");

	pushcli();
	mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
		sizeof(mycpu()->ts)-1, 0);
	SEG_CLS(mycpu()->gdt[SEG_TSS]);
	mycpu()->ts.ss0 = SEG_KDATA << 3;
	mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
	// setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
	// forbids I/O instructions (e.g., inb and outb) from user space
	mycpu()->ts.iomb = (ushort) 0xFFFF;
	ltr(SEG_TSS << 3);
	lcr3(V2P(p->pgdir));  // switch to process's address space
	popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
	char *mem;

	if(sz >= PGSIZE)
		panic("inituvm: more than a page");
	mem = kalloc();
	memset(mem, 0, PGSIZE);
	mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
	memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
	uint i, pa, n;
	pte_t *pte;

	if((uint) addr % PGSIZE != 0)
		panic("loaduvm: addr must be page aligned");
	for(i = 0; i < sz; i += PGSIZE){
		if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
			panic("loaduvm: address should exist");
		pa = PTE_ADDR(*pte);
		if(sz - i < PGSIZE)
			n = sz - i;
		else
			n = PGSIZE;
		if(readi(ip, P2V(pa), offset+i, n) != n)
			return -1;
	}
	return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
	char *mem;
	uint a;

	if(newsz >= KERNBASE)
		return 0;
	if(newsz < oldsz)
		return oldsz;

	a = PGROUNDUP(oldsz);
	for(; a < newsz; a += PGSIZE){
		mem = kalloc();
		if(mem == 0){
			cprintf("allocuvm out of memory\n");
			deallocuvm(pgdir, newsz, oldsz);
			return 0;
		}
		memset(mem, 0, PGSIZE);
		if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
			cprintf("allocuvm out of memory (2)\n");
			deallocuvm(pgdir, newsz, oldsz);
			kfree(mem);
			return 0;
		}
	}
	return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
	pte_t *pte;
	uint a, pa;

	if(newsz >= oldsz)
		return oldsz;

	a = PGROUNDUP(newsz);
	for(; a  < oldsz; a += PGSIZE){
		pte = walkpgdir(pgdir, (char*)a, 0);
		if(!pte)
			a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
		else if((*pte & PTE_P) != 0){
			pa = PTE_ADDR(*pte);
			if(pa == 0)
				panic("kfree");
			char *v = P2V(pa);
			kfree(v);
			*pte = 0;
		}
	}
	return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
	uint i;

	if(pgdir == 0)
		panic("freevm: no pgdir");
	deallocuvm(pgdir, KERNBASE, 0);
	for(i = 0; i < NPDENTRIES; i++){
		if(pgdir[i] & PTE_P){
			char * v = P2V(PTE_ADDR(pgdir[i]));
			kfree(v);
		}
	}
	kfree((char*)pgdir);	
}
// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
	pte_t *pte;

	pte = walkpgdir(pgdir, uva, 0);
	if(pte == 0)
		panic("clearpteu");
	*pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
	pde_t *d;
	pte_t *pte;
	uint pa, i, flags;
	char *mem;

	if((d = setupkvm()) == 0)
		return 0;
	for(i = 0; i < sz; i += PGSIZE){
		if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
			panic("copyuvm: pte should exist");
		if(!(*pte & PTE_P))
			panic("copyuvm: page not present");
		pa = PTE_ADDR(*pte);
		flags = PTE_FLAGS(*pte);
		if((mem = kalloc()) == 0)
			goto bad;
		memmove(mem, (char*)P2V(pa), PGSIZE);
		if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0) {
			kfree(mem);
			goto bad;
		}
	}
	return d;

bad:
	freevm(d);
	return 0;
}

// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
	pte_t *pte;

	pte = walkpgdir(pgdir, uva, 0);
	if((*pte & PTE_P) == 0)
		return 0;
	if((*pte & PTE_U) == 0)
		return 0;
	return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
	char *buf, *pa0;
	uint n, va0;

	buf = (char*)p;
	while(len > 0){
		va0 = (uint)PGROUNDDOWN(va);
		pa0 = uva2ka(pgdir, (char*)va0);
		if(pa0 == 0)
			return -1;
		n = PGSIZE - (va - va0);
		if(n > len)
			n = len;
		memmove(pa0 + (va - va0), buf, n);
		len -= n;
		buf += n;
		va = va0 + PGSIZE;
	}
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int broj_upisa = 0;
int getn(int pid,int alloc)
{
	int n=-1;int i;
	for(i=0;i<16;i++)
	{
		if(struktura[i].pid == pid)
		{
			n=i;
			break;
		}
	}
	if(alloc)	
	{
		if(i==16)
		{
			for(i=0;i<16;i++)
			{
				if(struktura[i].pid == 0)
				{	
					struktura[i].pid = pid;
					n=i;
					break;
				}
			}
		}
	}
	return n;
}
int fd, offset;

void *sys_mmap()
{
	
	pde_t *pgdir;
	pte_t *pte;
	int pid,n,i;
	char *addr;
	int addr1, length, perm, flags;
	argint(0,&addr1);argint(1,&length);argint(2,&perm);argint(3,&flags);argint(4,&fd);argint(5,&offset);
	
	addr = (char *)addr1;
	//cprintf("pid mmap %d\n", myproc()->pid);

	pgdir = myproc() -> pgdir;
	pid = myproc() -> pid;
	char * ret;
	n=getn(pid,1);
	if(addr > KERNBASE)
		return -1;
	if(length%PGSIZE != 0)
		return -1;
	//pomeranje offseta fajla	
	myproc()->ofile[fd] -> off = offset;
	struktura[n].rw=perm;
	for(i=0;i<length/PGSIZE;i++)
	{
		pte = walkpgdir(pgdir, addr+i*PGSIZE, 1);
		if(*pte & PTE_P)
		break;
	}
	
	if(i==length/PGSIZE)
	{
		for(i=0;i<length/PGSIZE;i++)
		{
			pte = walkpgdir(pgdir, addr+i*PGSIZE, 1);
			if(flags == 0 && myproc()->ofile[fd]->type == FD_SHM)
			{
				//cprintf("%p ", myproc()->ofile[fd]->adrese[myproc()->ofile[fd]->off]);
				*pte = V2P(myproc()->ofile[fd]->adrese[myproc()->ofile[fd]->off]) | 0 | PTE_P | PTE_U;
				myproc()->ofile[fd]->off +=1;	
				
			}
			else
			{
				char *v = kalloc();
				memset(v,0,PGSIZE);
				//logika za anonym


				if(flags==0)
				upisi(v,fd);			

				*pte = V2P(v) | perm | PTE_P | PTE_U;
			}
			dodaj(addr+i*PGSIZE,n);

			if(i==0)
			ret = addr;
		}	
	}
	//back
	else
	{
		int a = 1;
		addr = KERNBASE - a*length;
		
		while(1)
		{
			for(i=0;i<length/PGSIZE;i++)
			{
				pte = walkpgdir(pgdir, addr+i*PGSIZE, 1);
				if(*pte & PTE_P)
				break;
			}
			if(i==length/PGSIZE)
			{
				for(i=0;i<length/PGSIZE;i++)
				{
					pte = walkpgdir(pgdir, addr+i*PGSIZE, 1);
					if(flags == 0 && myproc()->ofile[fd]->type == FD_SHM)
					{
						//cprintf("%p ", myproc()->ofile[fd]->adrese[myproc()->ofile[fd]->off]);
						*pte = V2P(myproc()->ofile[fd]->adrese[myproc()->ofile[fd]->off]) | 0 | PTE_P | PTE_U;
						myproc()->ofile[fd]->off +=1;
								
					}
					else
					{
						char *v = kalloc();
						memset(v,0,PGSIZE);
						//logika za anonym


						if(flags==0)
						upisi(v,fd);			

						*pte = V2P(v) | perm | PTE_P | PTE_U;
					}
					dodaj(addr+i*PGSIZE,n);
					//cprintf("pointer %p\n", addr);
					if(i==0)
					ret = addr;
				}
				break;	
			}
			else
				a++;
		}
	}
	//ispisi(n);
	return ret;
}

void dodaj(char* va, int n)
{
	struktura[n].adrese[struktura[n].duzina] = va;
	struktura[n].duzina++;
}


void ispisi(int n)
{
	int i;
	pte_t *pte;
	char *v;
	for(i=0;i<struktura[n].duzina;i++)
	{
		cprintf("%p\n",struktura[n].adrese[i]);
		v = struktura[n].adrese[i];
		pte = walkpgdir(myproc()->pgdir, v, 0);
		//if(*pte!=0)
		{
			//v = P2V(PTE_ADDR(*pte));
			//cprintf("%p\n",v);
		}
	}
}

void upisi(char *v,int fd)
{
	
	if(myproc()->ofile[fd]->type != FD_SHM)
	{
		char niz[512];
		int ret=1;
		int brojac = 8;

		int prethodni=0;
		while(ret != 0 && brojac !=0)
		{
			ret = fileread(myproc()->ofile[fd], niz, 512);
			//if(ret<512)
			//niz[ret]=0;
			memmove(v+prethodni,niz,ret);
			prethodni += ret;
			brojac--;
		}
	}
	
}




int sys_msync()
{
	int addr1, length;
	argint(0,&addr1);argint(1,&length);
	char *addr = (char *)addr1;
	int n = getn(myproc()->pid,0);
	int i,ret;pte_t *pte;
	struct file * f = myproc()->ofile[fd];
	f->off = offset;
	length = length/PGSIZE;
	for(i=0;i<struktura[n].duzina;i++)
	{
		if(struktura[n].adrese[i]==addr)
		{
			int y=0;
			while(y<length)
			{
				char *v;
				pte = walkpgdir(myproc()->pgdir, struktura[n].adrese[i+y], 0);
				v = P2V(PTE_ADDR(*pte));
				char niz[512];
				//int ret = 512;
				int brojac = 0;
				//int prethodni = 0;
				while(*(v+brojac)!=0)
				{
					memmove(niz+brojac,v+brojac,1);
					brojac++;		
				}
				ret = filewrite(f,niz,brojac);
				y++;
			}
			break;
		}	
	}
	if(i==struktura[n].duzina)
	return -1;
	else
	return 0;
	
}



int mymunmap(char* v,int length)
{
	v = (char*)PGROUNDDOWN((uint)v);
	pde_t *pgdir;
	pte_t *pte;
	int n = getn(myproc()->pid,0);
	int i; length = length/4096;
	int j;
	int stara_duzina = struktura[n].duzina;
	for(i=0;i<stara_duzina;i++)
	{
		if(struktura[n].adrese[i] == v)
		{
			
			if(length > stara_duzina-i)
			length = stara_duzina-i;
			for(j=length;j>0;j--)
			{
				pte = walkpgdir(myproc()->pgdir, struktura[n].adrese[i+j-1], 0);
				v = P2V(PTE_ADDR(*pte));
				if(myproc()->ofile[fd]->type != FD_SHM)
				{
					kfree(v);
				}
					*pte=0;
				
			}
			
			for(j=i;j<struktura[n].duzina;j++)
			{
				if(j<struktura[n].duzina-length)
				struktura[n].adrese[j] = struktura[n].adrese[j+length];
				else
				struktura[n].adrese[j] = 0;
			}
			struktura[n].duzina-=length;
			break;
		}
	}
	
	if(i==stara_duzina)
	return -1;
	else
	return 0;
}

void clear_all(int pid)
{
	int n = getn(pid,0);
	if(n!=-1)
	{
		mymunmap(struktura[n].adrese[0],struktura[n].duzina*PGSIZE);
		struktura[n].pid = 0;
		struktura[n].duzina = 0;
		struktura[n].rw = 0;
	}
	broj_upisa=0;
}

int sys_munmap()
{
	int addr1, length;
	argint(0,&addr1);argint(1,&length);
	char *v = (char *)addr1;
	int ret = mymunmap(v,length);
	int n = getn(myproc()->pid,0);
	//ispisi(n);
	return ret;
	
}

int myfdalloc(struct file *f)
{
	int fd;
	struct proc *curproc = myproc();

	for(fd = 0; fd < NOFILE; fd++){
		if(curproc->ofile[fd] == 0){
			curproc->ofile[fd] = f;
			return fd;
		}
	}
	return -1;
}

int sys_shm_open()
{
	char *name;
	int omode;
	argptr(0,&name,sizeof(char *));argint(1,&omode);
	struct file *f;
	int i;
	begin_op();
	if(*name!='/')
	return -1;
	else
	{
		char *c= name+1;
		while(*c>0)
		{
			if(*c=='/')
			return -1;
			c++;
		}
	}
	
	if(omode & O_CREATE)
	{
		
		//for(i=shm_brojac;i<16;i++)
		{
			//if(shared[i].name == 0)
			//if(shared[i]==0)
			//break;
		}
		i=shm_brojac;
	}
		int y;int check = 0;
		for(y=0;y<shm_brojac;y++)
		{
			//if(!strncmp(shared[i].name,name,100))
			//if(shared[y] -> name != 0)
			{
				if(!memcmp(shared[y] -> name,name,100))
				{
					i = y;
					check = 1;
					break;
				}
			}
			
		}	
	if(!(omode & O_CREATE) && check==0)
	return -1;
	
	if((shared[i] = filealloc()) == 0 || (fd = myfdalloc(shared[i])) < 0){
		if(shared[i])
			fileclose(shared[i]);
		end_op();
		return -1;
	}
	end_op();
	
	if(i==shm_brojac)
	{
		shared[i]->type = FD_SHM;
		shared[i]->ip = 0;
		shared[i]->off = 0;
		shared[i]->readable = !(omode & O_WRONLY);
		shared[i]->writable = (omode & O_WRONLY) || (omode & O_RDWR);
		shared[i]->size = 0;
		shared[i] -> name = name;
		shared[i] -> stat = 0;
		shm_brojac++;
	}
	return fd;
}

sys_shm_unlink()
{
	//struct file * shared[16];
	//int shm_brojac=0;
	char *name;
	argptr(0,&name,sizeof(char *));
	struct file *f;
	int i,y;
	for(i=0;i<shm_brojac;i++)
	{
		f = shared[i];
		if(!strncmp(f->name,name,100))
		{
			for(y=0;y < f-> size/PGSIZE;y++)
			{
				kfree(f->adrese[y]);
			}
			f-> size = 0;
			f -> name = 0;
			shared[i] -> stat = 0;
		}
		break;
	}
	if(i==shm_brojac)
	return -1;
	for(i;i<shm_brojac-1;i++)
	{
		shared[i] = shared[i+1];
	}
	shm_brojac--;
	return 0;
}
sys_ftruncate()
{
	int fd;
	int length;
	argint(0,&fd);argint(1,&length);
	struct file *f = myproc()->ofile[fd];
	int duzina = length/PGSIZE;
	int i;
	char *v;
	if(duzina > f->size)
	{
		duzina = duzina	- f->size;
		for(i=0;i<duzina;i++)
		{
			v = kalloc();
			//cprintf("pointer %p\n",v);
			memset(v,0,PGSIZE);
			f -> adrese[f->size+i] = v;
		}
		f->size += duzina;
	}
	else
	{
		duzina = f->size - duzina;
		for(i=0;i<duzina;i++)
		{
			kfree(f -> adrese[f->size-i]);
		}
		f->size -= duzina;
	}
	return 0;
	
}    

int pomocna()
{
	int ret = 0;
	if(myproc()->ofile[fd]->type == FD_SHM)
	ret = 1;
	//cprintf("dobar\n");
	return ret;
	
}
pte_t * pomocna2(pde_t *pgdir, const void *va, int alloc)
{
	va = (char*)PGROUNDDOWN((uint)va);
	return walkpgdir(pgdir, va,alloc);
}


int sys_shm_stat()
{
	int fd;
	argint(0,&fd);
	return myproc()->ofile[fd]->stat;
}

void pomocna3()
{
	broj_upisa++;
	if(broj_upisa<2)
	myproc()->ofile[fd]->stat++;
}



int pomocna4()
{
	int n = getn(myproc()->pid,0);
	if(struktura[n].rw==0)
	return 0;
	else
	return 1;
}













