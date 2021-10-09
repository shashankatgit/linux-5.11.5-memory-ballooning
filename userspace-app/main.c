#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <stdint.h>
#include <sys/time.h>

#include "testcases.h"

void *buff;
unsigned long nr_signals = 0;

#define PAGE_SIZE		(4096)

#define SIGBALLOON (SIGRTMAX-1)
#define INIT_BALLOON_SYSCALL_NO 442
#define MB_SUGGEST_SWAP_SYSCALL_NO 443

#define MIN(x,y) (x<y? x:y)

#define FREE_PAGES (sysconf(_SC_AVPHYS_PAGES))
#define FREE_MEM_BYTES (FREE_PAGES*PAGE_SIZE)

// Goal for free memory : Pages equivalent to 1 GB
#define FREE_PGS_TARGET (1<<18) 

// Suggest this many extra pages : Pages equivalent to 4 MBs
#define FREE_PGS_TARGET_EXTRA (1<<10) 

// Cap on number of pages to suggest : 2^15 pages = 128 MB 
#define N_SUGGEST_PAGES_MAX_LIMIT ((1<<15)) 

/*
 * Size for idle bitmap buffer
 * Can hold idle bits for (MAX_IDLEMAP_SIZE*8) page frames 
 *			= 8*(MAX_IDLEMAP_SIZE>>18) GBs
 * Currently enough for 32 GB physical memory
 */ 
#define MAX_IDLEMAP_SIZE	((1<<20)) 

// Read unit size for /sys/kernel/mm/page_idle/bitmap
#define IDLEMAP_READ_SIZE	8

// Write unit size for /sys/kernel/mm/page_idle/bitmap
#define IDLEMAP_WRITE_SIZE	4096

// Both pagemap and idlemap are organised as 8 byte chunks
#define IDLEMAP_BLOCK_SIZE 8
#define PAGEMAP_BLOCK_SIZE 8

// Bit mask for calculating PFN and testing if frame present
#define PFN_MASK (~(0x1ffLLU << 55))
#define PG_PRESENT_MASK (0x1LLU << 63)

// For THP related tasks
#define HUGE_PG_MASK (0x1LLU<<22)
#define PAGEFLAGS_BLOCK_SIZE 8
#define MAX_HUGEPG_BUF_SIZE	((1<<23)) //1B for every PFN, enough for 32 GB phy memory


char *pge_idle_bmp = "/sys/kernel/mm/page_idle/bitmap";

int *buf_start_va;
long long buf_size_bytes;
long long buf_n_pages;

unsigned long long *idle_map_buf;
unsigned long long idle_map_buf_size;

pid_t my_pid;

// Final list of VAs to be sent to kernel
unsigned long long *va_pg_list;

unsigned long long pagemap_buf_size;
unsigned long long *pagemap_buf;

// Buffer to save whether a pfn is a part of a THP
char *huge_page_buf;
unsigned long long huge_page_buf_size;

struct pg_idle_score {
	unsigned long long va;
	short int idleness_score;
};

short int *idle_score_arr;

struct pg_idle_score *pg_idle_score_arr;
unsigned long long pg_idle_score_arr_count;

/*
 * Defined at the bottom of this file
 */
int compare(const void *a, const void *b);
int set_bits_of_idlemap();
int sync_idle_map();


#define SLEEP_TIME_STEP_INCR 4
#define MAX_SLEEP_TIME 24
#define MIN_SLEEP_TIME 6
#define WSET_ESTIMATION_TIME 6
void *thread_refresh_idle_bitmap(void *vargp)
{
	unsigned long nr_signals_prev;

	nr_signals_prev = nr_signals;
	int sleep_time_sec = MIN_SLEEP_TIME;
	int tmp_sleep_time_sec;
	unsigned short int cnt_same_n_signal = 0;

	struct timeval ts_start, ts_end;
	unsigned long long ts_tot_exec_us;

	for(;;) {
		gettimeofday(&ts_start, NULL);
		if(nr_signals == nr_signals_prev) {
			if(cnt_same_n_signal<4)
				cnt_same_n_signal++;
		} else {
			cnt_same_n_signal = 0;
		}

		// Load map only if we have seen at least 1 new signal 
		// in last 3 iterations
		if(cnt_same_n_signal<4) {
			sync_idle_map();
		}

		sleep(sleep_time_sec);
		set_bits_of_idlemap();

		sleep(WSET_ESTIMATION_TIME);
	}
}


/*
 * THP Related Functions
 *   - load_hugepages_buffer : 	byte buffer to tell whether the indexed pfn 
 *								lies on a THP
 *   - is_huge_page_cached : 	given a pfn, use buffer to tell whether it 
 * 								lies on a THP
 */
void load_hugepages_buffer(){
    int kpageflagsfd;

    unsigned long long bits;
	char *p;

    if ((kpageflagsfd = open("/proc/kpageflags", O_RDONLY)) < 0) {
		perror("Can't read kpageflags file");
		exit(1);
	}

	p = huge_page_buf;

	int bytes_read;
	long long i=0;
	while ((bytes_read = read(kpageflagsfd, &bits, PAGEFLAGS_BLOCK_SIZE)) > 0) {
		if(bits & HUGE_PG_MASK){
			p[i] = 1;
		}
    
		else {
			p[i]=0;
		}
		i++;
	}
	huge_page_buf_size = i;

	close(kpageflagsfd);
}

int is_huge_page_cached(unsigned long long pfn) {
	return (int)huge_page_buf[pfn];
}

/*
 * 			placeholder-3
 * implement your page replacement policy here
 */

/* Brief description of policy 
 * The policy uses a scoring mechanism to decide which pages to swap out.
 * Higher score means greater likelihood of being swapped out.
 * The score (range : 0 to 1000) depends on following parameters.
 * 		1. The history of the page to the best of knowledge
 *		2. The proximity(spatial) to busy pages seen before the page 
 *		3. Randomness distributed spatially across the page range
 *		4. Whether the page is part of a THP
 *
 * The code to read pagemaps and idle page bitmap is heavily inspired from
 * Brendan Gregg's github repo "Working Set Size (WSS) Tools for Linux"
 * (https://github.com/brendangregg/wss). The idea to do large writes 
 * and copy the data into memory and then operating on it is totally 
 * borrowed from there.
 */

// Upper limit on scores alotted to pages
#define MAX_IDLENESS_SCORE 1000

#define SCORE_GRADIENT_MAX 20
#define SCORE_GRADIENT_STEP_SIZE 1
#define SCORE_GRADIENT_DIR_INCR 1
#define SCORE_GRADIENT_DIR_DECR 2
#define SCORE_MAX_BOOST_DISTANCE 8
#define SCORE_MAX_BOOST 300
#define SCORE_THP_DISCOUNT 350 // Discourage swapping of THPs
unsigned long long prepare_swappable_page_list(long long n_exp_suggested_pgs) {
	// expecting the global array va_pg_list to be already mallocated in main
	unsigned long long i, j, k;
	unsigned long buf_start_va_pg_aligned = ((unsigned long)buf_start_va & ~(PAGE_SIZE-1));
	unsigned long long n_suggested_pgs;
	
	unsigned long long *p;
	int pagefd;
	char pagepath[128];
	unsigned long long offset, pagemapp, pfn, idlemapp, idlebits, page_present;
	unsigned long long is_page_idle_long;
	short int is_page_idle_short;
	short int idle_score_low, idle_score_high;
	unsigned long long n_pages_abs, n_pages_range_1, n_pages_range_2, n_pages_range_3,
			n_pages_range_4, n_pages_range_5;
	unsigned long long n_thp_pages;
	unsigned short cur_score_gradient;
	unsigned short cur_score_gradient_dir;
	unsigned long long dist_from_last_busy_page;
	unsigned short busy_pg_proximity_boost;
	short is_hugepage;
	unsigned short thp_discount;
	short int cur_idleness_score;
	

	printf("prepare_swappable_page_list called with n_exp_suggested_pgs = %lld\n", n_exp_suggested_pgs);

	sprintf(pagepath, "/proc/%d/pagemap", my_pid);

	if ((pagefd = open(pagepath, O_RDONLY)) < 0) {
		perror("Can't read pagemap file");
		exit(1);
	}

	// cache pagemap to get PFN, then operate on PFN from idlemap
	offset = PAGEMAP_BLOCK_SIZE * buf_start_va_pg_aligned / PAGE_SIZE;
	if (lseek(pagefd, offset, SEEK_SET) < 0) {
		printf("Can't seek pagemap file\n");
		exit(1);
	}
	p = pagemap_buf;

	// optimized: read this in one syscall
	if (read(pagefd, p, pagemap_buf_size) < 0) {
		perror("Read page map failed.");
		exit(1);
	}

	close(pagefd);

	load_hugepages_buffer();

	n_suggested_pgs=0;
	pg_idle_score_arr_count=0;
	cur_score_gradient = 0;
	dist_from_last_busy_page = SCORE_MAX_BOOST_DISTANCE+1;
	cur_score_gradient_dir=SCORE_GRADIENT_DIR_INCR;
	n_pages_abs=n_pages_range_1=n_pages_range_2=n_pages_range_3=0;
	n_pages_range_4=n_pages_range_5=0;
	n_thp_pages=0;
	for (i = 0; i < buf_n_pages; i++, dist_from_last_busy_page++) {

		if (cur_score_gradient_dir == SCORE_GRADIENT_DIR_INCR)
			cur_score_gradient += SCORE_GRADIENT_STEP_SIZE;
		else
			cur_score_gradient -= SCORE_GRADIENT_STEP_SIZE;

		if(cur_score_gradient >= SCORE_GRADIENT_MAX) {
			cur_score_gradient = SCORE_GRADIENT_MAX;
			cur_score_gradient_dir = SCORE_GRADIENT_DIR_DECR;
		} else if(cur_score_gradient <= 0) {
			cur_score_gradient = 0;
			cur_score_gradient_dir = SCORE_GRADIENT_DIR_INCR;
		}


		// convert virtual address p to physical PFN
		pfn = p[i] & PFN_MASK;
		page_present = p[i] & PG_PRESENT_MASK;
		if (pfn == 0 || page_present == 0) {
			// if page is not present, then mark its idle score -1 
			// (so that it is not suggested for swapping) and continue
			idle_score_arr[i] = -1;
			n_pages_abs++;
			continue;
		}
	
		// Check if current virtual page is backed by THP
		is_hugepage = is_huge_page_cached(pfn);

		// read idle bit
		idlemapp = (pfn / 64) * IDLEMAP_BLOCK_SIZE;
		if (idlemapp > idle_map_buf_size) {
			printf("ERROR: bad PFN read from page map.\n");
			idle_score_arr[i] = -1;
			continue;
		}
		idlebits = idle_map_buf[idlemapp];

		// boost page history score if it is in proximity of busy pages
		busy_pg_proximity_boost = 0;
		if(dist_from_last_busy_page < SCORE_MAX_BOOST_DISTANCE) {
			busy_pg_proximity_boost = SCORE_MAX_BOOST;
		}

		//if page is idle, include in list
		is_page_idle_long = idlebits & (1ULL << (pfn % 64));
		if(is_page_idle_long) {
			is_page_idle_short = 1;
		}
		else {
			is_page_idle_short = 0;
			dist_from_last_busy_page = 0;
		}

		/*
		 * If the page was initially swapped out but later swapped in,
		 * this indicates that this could be a frequently used page, 
		 * so its history should be accordingly set.
		 */
		if(idle_score_arr[i] < 0)
			idle_score_arr[i] = 0;
		
		/*
		 * Boost (reduce) the score before calculating new score if this
		 * page is in proximity to busy pages.
		 */
		if(busy_pg_proximity_boost && idle_score_arr[i] > busy_pg_proximity_boost) {
			idle_score_arr[i] -= busy_pg_proximity_boost;
		}

		/*
		 * Calculate new score for the page. 
		 * Current ratio for history:fresh :: 6:4
		 * This is a sort of ageing mechanism which incorporates randomness
		 * and spatial locality(due to proximity boost)
		 */
		idle_score_arr[i] = (short int)(0.6* (float)idle_score_arr[i]) + 400*is_page_idle_short;
		pg_idle_score_arr[pg_idle_score_arr_count].va = buf_start_va_pg_aligned + (i)*PAGE_SIZE;

		
		// gradient is not to be remembered as history
		if((idle_score_arr[i] + cur_score_gradient) < MAX_IDLENESS_SCORE) {
			cur_idleness_score = idle_score_arr[i] + cur_score_gradient;
		} else {
			pg_idle_score_arr[pg_idle_score_arr_count].idleness_score = MAX_IDLENESS_SCORE;
		}

		// If already not minimum, reduce the idleness score of THP pages
		// It too doesn't need to be remembered
		if(cur_idleness_score >= SCORE_THP_DISCOUNT) {
			cur_idleness_score -= SCORE_THP_DISCOUNT;
		}

		pg_idle_score_arr[pg_idle_score_arr_count].idleness_score = cur_idleness_score;
		
		pg_idle_score_arr_count++;

		/* 
		 * Keep track of number of pages in different score ranges purely
		 * for the purpose of seeing if scoring is sensible or stupid
		 */ 
		if(idle_score_arr[i] >= 800) {
			n_pages_range_1++;
		} else if (idle_score_arr[i] >= 600) {
			n_pages_range_2++;
		} else if (idle_score_arr[i] >= 300) {
			n_pages_range_3++;
		} else if (idle_score_arr[i] >= 100) {
			n_pages_range_4++;
		} else {
			n_pages_range_5++;
		}

		if(is_hugepage) {
			n_thp_pages++;

			// cuurent page is the head of THP, so skip next 511 pages 
			// as they all have same idle bits
			i+=511;
		}
	}


	// Sort the score array
	qsort (pg_idle_score_arr, pg_idle_score_arr_count, sizeof(struct pg_idle_score), compare);
	
	/*
	 * Reporting the statistics collected above
	 * Couldn't resist not commenting or deleting this
	 */
	printf("Counts of pages in different ranges : \n");
	printf("Range 1 (IdleScore >= 800) : %llu\n", n_pages_range_1);
	printf("Range 2 (IdleScore >= 600) : %llu\n", n_pages_range_2);
	printf("Range 3 (IdleScore >= 300) : %llu\n", n_pages_range_3);
	printf("Range 3 (IdleScore >= 100) : %llu\n", n_pages_range_4);
	printf("Range 3 (IdleScore >= 0) : %llu\n", n_pages_range_5);
	printf("Absent or Swapped : %llu\n", n_pages_abs);
	printf("THP : %llu\n\n", n_thp_pages);


	/* 
	 * Choose n_exp_suggested_pgs from the array in decreasing order
	 * of idleness score.
	 */
	for(n_suggested_pgs=0; n_suggested_pgs<n_exp_suggested_pgs; n_suggested_pgs++) {
		va_pg_list[n_suggested_pgs] = pg_idle_score_arr[n_suggested_pgs].va;
	}

	return n_suggested_pgs;
}

void try_to_suggest_swap_pages(void){
	int syscall_ret_val;

	long long n_pgs_needed = FREE_PGS_TARGET - FREE_PAGES;
	long long n_exp_suggested_pgs;
	long long n_act_suggested_pgs;

	struct timeval ts_start, ts_end;
	unsigned long long ts_tot_exec_us;

	printf("Need %lld MBs to cross free memory threshold\n", n_pgs_needed>>8);
	
	/*
	 * If the pages actually needed are too little, at least free
	 * FREE_PGS_TARGET_EXTRA pages, otherwise free additional 
	 * FREE_PGS_TARGET_EXTRA pages.
	 */
	if (n_pgs_needed < FREE_PGS_TARGET_EXTRA)
		n_exp_suggested_pgs = FREE_PGS_TARGET_EXTRA;
	else 
		n_exp_suggested_pgs = n_pgs_needed +  FREE_PGS_TARGET_EXTRA;

	// Don't suggest more pages than N_SUGGEST_PAGES_MAX_LIMIT
	if(n_exp_suggested_pgs > N_SUGGEST_PAGES_MAX_LIMIT)
		n_exp_suggested_pgs = N_SUGGEST_PAGES_MAX_LIMIT;

	gettimeofday(&ts_start, NULL);
	n_act_suggested_pgs = prepare_swappable_page_list(n_exp_suggested_pgs);
	gettimeofday(&ts_end, NULL);

	ts_tot_exec_us = 1000000 * (ts_end.tv_sec - ts_start.tv_sec) +
	    (ts_end.tv_usec - ts_start.tv_usec);
	printf("Total execution time for preparing page list : %.3f seconds\n", (double)ts_tot_exec_us/1000000);

	if(n_act_suggested_pgs) {
		syscall_ret_val = syscall(MB_SUGGEST_SWAP_SYSCALL_NO, va_pg_list, n_act_suggested_pgs);
	}
}

/*
 * 			placeholder-2
 * implement your signal handler here
 */
void SIGBALLOON_handler(int sig)
{
	struct timeval ts_handler_start, ts_handler_end;
	unsigned long long ts_tot_exec_us;
	gettimeofday(&ts_handler_start, NULL);
    ++nr_signals;
	printf("Received SIGBALLOON signal %lu from the kernel\n", nr_signals);

	/*
	 * This function will take care of preparing the list of pages to swap 
	 * and sending to kernel
	 */
	try_to_suggest_swap_pages();
	gettimeofday(&ts_handler_end, NULL);

	ts_tot_exec_us = 1000000 * (ts_handler_end.tv_sec - ts_handler_start.tv_sec) +
	    (ts_handler_end.tv_usec - ts_handler_start.tv_usec);

	printf("Total sighandler execution time : %.3f seconds\n", (double)ts_tot_exec_us/1000000);
}

int main(int argc, char *argv[])
{
	int *ptr, nr_pages;

	int syscall_ret_val;
	pthread_t thread_id;
	struct timeval ts_prog_start, ts_prog_end;
	unsigned long long ts_tot_exec_us;
	unsigned long i;

	gettimeofday(&ts_prog_start, NULL);

	my_pid = getpid();

	printf("TOTAL_MEMORY_SIZE (BUFFER SIZE): %ld", TOTAL_MEMORY_SIZE);

    ptr = mmap(NULL, TOTAL_MEMORY_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

	buf_start_va = ptr;
	buf_size_bytes = TOTAL_MEMORY_SIZE;
	buf_n_pages = buf_size_bytes/PAGE_SIZE;

	printf("TOTAL_PAGES_IN_BUFFER : %lld", buf_n_pages);

	if (ptr == MAP_FAILED) {
		printf("mmap failed for buffer\n");
       		exit(1);
	}
	buff = ptr;
	memset(buff, 0, TOTAL_MEMORY_SIZE);

	if ((idle_map_buf = malloc(MAX_IDLEMAP_SIZE)) == NULL) {
		printf("Can't allocate memory for idlemap buf (%d bytes)",
		    MAX_IDLEMAP_SIZE);
		exit(1);
	}

	// Do a sync_idle_map, so that garbage in idlemap is never read
	set_bits_of_idlemap();
	sync_idle_map();

	if ((idle_score_arr = malloc(sizeof(unsigned int) * buf_n_pages)) == NULL) {
		printf("Can't allocate memory for idle_score_arr (%lld bytes)",
		    sizeof(unsigned int) * buf_n_pages);
		exit(1);
	}
	// Initially every page score is marked as fully idle
	for(i=0 ; i<buf_n_pages; i++) idle_score_arr[i]=MAX_IDLENESS_SCORE-SCORE_GRADIENT_MAX;

	if ((pg_idle_score_arr = malloc(sizeof(struct pg_idle_score) * buf_n_pages)) == NULL) {
		printf("Can't allocate memory for pg_idle_score array (%lld bytes)",
		    sizeof(struct pg_idle_score) * buf_n_pages);
		exit(1);
	}

	va_pg_list = (unsigned long long *)malloc(sizeof(unsigned long long)*N_SUGGEST_PAGES_MAX_LIMIT);
	if(va_pg_list == NULL) {
		printf("malloc failed for va_pg_list!\n\n\n");
		exit(1);
	}

	pagemap_buf_size = (PAGEMAP_BLOCK_SIZE * buf_n_pages);
	if ((pagemap_buf = malloc(pagemap_buf_size)) == NULL) {
		printf("Can't allocate memory for pagemap buf (%lld bytes)",
		    pagemap_buf_size);
		exit(1);
	}

	// Spawn the thread which will periodically refresh the idlemap
	pthread_create(&thread_id, NULL, thread_refresh_idle_bitmap, NULL);

	if ((huge_page_buf = malloc(MAX_HUGEPG_BUF_SIZE)) == NULL) {
		printf("Can't allocate memory for hugepage buf (%d bytes)",
		    MAX_HUGEPG_BUF_SIZE);
		exit(1);
	}

	printf("Installing handler for SIGBALLOON\n");
	signal(SIGBALLOON, SIGBALLOON_handler); 

	/*
	 * 		placeholder-1
	 * register me with the kernel ballooning subsystem
	 */
	syscall_ret_val = syscall(INIT_BALLOON_SYSCALL_NO);
	if(syscall_ret_val) {
		printf("Error : Failed to register with ballooning driver\n");
	}

	/* test-case */
	test_case_main(buff, TOTAL_MEMORY_SIZE);


	munmap(ptr, TOTAL_MEMORY_SIZE);
	gettimeofday(&ts_prog_end, NULL);
	ts_tot_exec_us = 1000000 * (ts_prog_end.tv_sec - ts_prog_start.tv_sec) +
	    (ts_prog_end.tv_usec - ts_prog_start.tv_usec);

	printf("I received SIGBALLOON %lu times\n", nr_signals);
	printf("Total execution time : %.3f seconds\n", (double)ts_tot_exec_us/1000000);
	free(idle_map_buf);
	free(va_pg_list);
	free(pagemap_buf);
	free(idle_score_arr);
	free(pg_idle_score_arr);
}


/*
 * Functions which need less attention defined here and declared at the top
 */
int compare(const void *a, const void *b)
{
  short int idle_score1 = ((struct pg_idle_score *)a)->idleness_score;
  short int idle_score2 = ((struct pg_idle_score *)b)->idleness_score;

  // we want sort descending, larger element should come first
  if(idle_score1 < idle_score2) 
    return 1;
  else if(idle_score1 == idle_score2)
    return 0;
  else 
    return -1; 
}

int set_bits_of_idlemap()
{
	char *p;
	int idle_fd, i;
	
	char buf[IDLEMAP_WRITE_SIZE];

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = 0xff;

	
	if ((idle_fd = open(pge_idle_bmp, O_WRONLY)) < 0) {
		perror("Can't write idlemap file");
		exit(2);
	}

	// set all the bits in the idlemap, kernel pages will be silently ignored
	while (write(idle_fd, &buf, sizeof(buf)) > 0) {;}
	close(idle_fd);

	return 0;
}

int sync_idle_map()
{
	unsigned long long *p;
	int idle_fd;
	ssize_t len;
	unsigned long long idle_map_buf_size_local;

	// load the idlemap to memory
	if ((idle_fd = open(pge_idle_bmp, O_RDONLY)) < 0) {
		perror("Can't read idlemap file");
		exit(2);
	}
	p = idle_map_buf;
	idle_map_buf_size_local = 0;

	// as per Brendan Gregg, larger reads are not allowed for some reason
	while ((len = read(idle_fd, p, IDLEMAP_READ_SIZE)) > 0) {
		p += IDLEMAP_READ_SIZE;
		idle_map_buf_size_local += len;
	}
	idle_map_buf_size = idle_map_buf_size_local;
	close(idle_fd);

	return 0;
}