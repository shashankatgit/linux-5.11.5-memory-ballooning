#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
// #include <linux/swap.h> 

#include <linux/mm.h>
#include <linux/mman.h>

#include <linux/syscalls.h>
#include <linux/mmzone.h>

#include <linux/workqueue.h>


/*
 * Author : Shashank Singh (shashanksing@iisc.ac.in, cse.shashanksingh@gmail.com)
 * Contains the definition for following system calls for 64 bit linux kernel.
 *      - init_ballooning : used by userspace appl. to register to ballooning driver
 *      - mb_suggest_swap : used by userspace appl. to suggest a list of pages to 
 *        swap out
 */

#define SIG_BALLOON (SIGRTMAX-1)
#define PAGE_SIZE_BYTES (4096)

/*
 * This number of pages will be attempted to be freed from inactive
 * list if they've completed WB to swapfile. Current value is 3*128 MB
*/
#define N_RECLAIM_INACT_PAGES (3*(1<<15))

#define DEBUG 1
#if defined(DEBUG) && DEBUG > 0
    #define DEBUG_PRINT(fmt, args...) printk("KDEBUG: %s:%d:%s(): " fmt, \
        __FILE__, __LINE__, __func__, ##args)
#else
    #define DEBUG_PRINT(fmt, args...) /* Don't do anything when DEBUG is off or absent */
#endif


/*
 * Flag that denotes whether memory ballooning some process has
 * registered for memory ballooning. This flag is used to send 
 * SIGBALLOON to the process as well as disabling anon page 
 * swapping in vm_scan.c
 */
int mem_balloon_is_active=0;

/*
 * Flag that denotes whether a signal should be sent to process
 * when free phy mem falls below threshold. Used to implement 
 * the wait time of 10 seconds before sending another signal.
 */
int mem_balloon_should_send_signal=1;

/*
 * The pid of the process currently registered for memory
 * ballooning. Used to send the SIGBALLOON signal to the process.
 */
pid_t mem_balloon_reg_task_pid;

/*
 * New function added to mm/vmscan.c, it is practically a copy of already
 * existing function shrink_all_memory in the same file. This one has a 
 * different scan_control and is used for freeing unmapped pages after 
 * their writeback to swap completes.
*/
extern unsigned long mb_shrink_all_memory(unsigned long nr_to_reclaim);

/* We'll use this to schedule setting the above flag after x seconds */
static struct delayed_work mem_balloon_flag_set_delayed_work;

/* 
 * Threshold for initiating memory ballooning signal in terms of pages
 * To make the threshold architecture and page size independent
 * For example, if PAGE_SHIFT = 12 (for 4KB Pages)
 * then, 1 GB = 1048576 KB = 1048576 KB/4 KB = 262144 pages 
 */
#define MEM_BALLOON_THRESHOLD_PAGES (1048576 >> (PAGE_SHIFT-10))
#define SIG_BALLOON (SIGRTMAX-1)
void mem_balloon_set_signal_flag_work_handler(struct work_struct *work)
{
    struct kernel_siginfo mem_balloon_siginfo;
	unsigned long n_free_physical_pages;
	struct task_struct* mem_balloon_reg_process_task_struct;

	printk("Checking free memory status and deciding to send signal\n");
    if (mem_balloon_is_active==1) {
		/* 
		 * Check if we have a valid pid is registered with us 
		 */
		if (mem_balloon_reg_task_pid>0) {
            n_free_physical_pages = global_zone_page_state(NR_FREE_PAGES);
			if (n_free_physical_pages  < MEM_BALLOON_THRESHOLD_PAGES) {
				memset(&mem_balloon_siginfo, 0, sizeof(struct kernel_siginfo));
				
				mem_balloon_siginfo.si_signo = SIG_BALLOON;
				mem_balloon_siginfo.si_code = SI_KERNEL;
				mem_balloon_siginfo.si_int = 1234; 
				
				rcu_read_lock();
				mem_balloon_reg_process_task_struct = pid_task(find_get_pid(mem_balloon_reg_task_pid), 
														PIDTYPE_PID);
				rcu_read_unlock();

				/* If the registered process hasn't died yet, only then send the signal */
				if (mem_balloon_reg_process_task_struct) {
					if (send_sig_info(SIG_BALLOON, &mem_balloon_siginfo, mem_balloon_reg_process_task_struct) < 0) {
						printk("error sending SIGBALLOON signal in page_alloc.c\n");
					}

					/* Unset the flag so that no signal should be sent till the flag is set again */
					mem_balloon_should_send_signal=0;
					
                    
				}
				/* If the process has died, unset the saved pid to avoid unnecessary efforts */
				else {
					printk("No process found with the pid so resetting the saved pid\n");
					mem_balloon_reg_task_pid=-1;
				}
			}
		}
    }

    /* Schedule a work item in the work queue to set the flag after x (10) seconds */
    INIT_DELAYED_WORK(&mem_balloon_flag_set_delayed_work, 
                    mem_balloon_set_signal_flag_work_handler);
    schedule_delayed_work(&mem_balloon_flag_set_delayed_work, 10*HZ);
}


/* 
 * Implementation of register ballooning system call.
 * As soon as this syscall is invoked, mem_balloon_is_active flag is set, which disables
 * swapping systemwide. The added code in get_scan_count in vmscan.c does this.
 */
    /*
     * Following approaches were explored to disable swapping of anon pages
     *  - Pinning of process pages in RAM 
     *  - Bypassing the swapping mechanism in shrink_page_list
     *  - Changing the scan balance of get_scan_count - This by far seems to be 
     *    the best one, considering it has a very clean code change and just instructs
     *    that no anon page must be swapped. So, kernel won't even try to loop
     *    through anon pages.
     */
SYSCALL_DEFINE0(init_ballooning){
    DEBUG_PRINT("init_ballooning syscall has been called\n");
    DEBUG_PRINT("PID of calling process is : %d\n", current->pid);

    /* 
     * Save the current process to send the SIGBALLOON signal when needed
     * Also, mark the mem_balloon_is_active flag to enable the check
     * for physical memory.
    */  
    mem_balloon_reg_task_pid = current->pid;
    
    if(mem_balloon_is_active == 0) {
        mem_balloon_is_active = 1;
        DEBUG_PRINT("Since, this is first syscall invoc, invoking work item for signalling mechanism\n");
        INIT_DELAYED_WORK(&mem_balloon_flag_set_delayed_work, 
                                        mem_balloon_set_signal_flag_work_handler);
        schedule_delayed_work(&mem_balloon_flag_set_delayed_work, 2);
    }
    mem_balloon_is_active = 1;

    return 0;
}


/* 
 * Implementation of mb_suggest_swap system call.
 * Will be used by userspace application to suggest pages to swap
 * Input : an array of start VAs of pages to swap out, size of the array
 */
    /*
    * The PA vs VA dilemma : There are two options when suggesting pages to 
    * swap out :
    *   1. Suggesting physical page frames
    *   2. Suggesting virtual page numbers
    * The first is a breach of security as no door should be opened to 
    * userspace to manipulate physical pages directly as they don't respect 
    * process isolation and concern boundaries. So, I went ahead with virtual 
    * pages although there's a slightperformance impact due to the repeated 
    * VA->PA translation involved before swapping.  
    */
SYSCALL_DEFINE2(mb_suggest_swap, unsigned long long* __user, virt_pg_list_start, 
                    unsigned long long, list_size){
    unsigned i;
    struct mm_struct *cur_mm =  current->mm;
    unsigned long long va_pg_start;

    unsigned long long *virt_pg_list_kernel;
    unsigned long long n_bytes_uncopied;

    int ret_val_madvise;
    unsigned long long ret_free_pages = 0;
    unsigned long n_to_shrink_pages;

    DEBUG_PRINT("mb_suggest_swap syscall:: list start: %px, list size : %llu\n", virt_pg_list_start, list_size);

    virt_pg_list_kernel = kmalloc(sizeof(unsigned long long)*list_size,GFP_KERNEL);

    n_bytes_uncopied = copy_from_user(virt_pg_list_kernel, virt_pg_list_start, sizeof(unsigned long long)*list_size);

    if(n_bytes_uncopied) {
        DEBUG_PRINT("mb_suggest_swap syscall::copy_to_user couldn't copy %llu bytes\n", n_bytes_uncopied);
    }

    for(i=0; i<list_size; ++i) {
        va_pg_start = *(virt_pg_list_kernel+i);

        ret_val_madvise = do_madvise(cur_mm, va_pg_start, PAGE_SIZE_BYTES, MADV_PAGEOUT);
        if(ret_val_madvise) {
            DEBUG_PRINT("------ERROR : do_madvise failed and returned non zero value for VA : %llx --------\n", va_pg_start);
            break;
        }
    }

    kfree(virt_pg_list_kernel);
    
    n_to_shrink_pages = (unsigned long )list_size;

    /*
     * Try to claim at least N_RECLAIM_INACT_PAGES from inactive anon lru 
     * list, which have completed write to swap 
    */
    if(n_to_shrink_pages < N_RECLAIM_INACT_PAGES) {
        n_to_shrink_pages = N_RECLAIM_INACT_PAGES;
    }
    ret_free_pages = mb_shrink_all_memory(n_to_shrink_pages);
    DEBUG_PRINT("mb_suggest_swap syscall:: mb_shrink_all_memory freed %llu pages = %llu MB\n", ret_free_pages, ret_free_pages>>8);

    return 0;
}

