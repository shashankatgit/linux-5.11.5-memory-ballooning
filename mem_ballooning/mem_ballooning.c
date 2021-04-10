#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/swap.h> 

/*
 * Author : Shashank Singh (shashanksing@iisc.ac.in, cse.shashanksingh@gmail.com)
 * Contains the definition for a system call init_ballooning for 64 bit linux kernel.
 */

#define SIG_BALLOON (SIGRTMAX-1)


#define DEBUG 1
#if defined(DEBUG) && DEBUG > 0
    #define DEBUG_PRINT(fmt, args...) printk("KDEBUG: %s:%d:%s(): " fmt, \
        __FILE__, __LINE__, __func__, ##args)
#else
    #define DEBUG_PRINT(fmt, args...) /* Don't do anything when DEBUG is off or absent */
#endif


struct task_struct *mem_balloon_reg_task = NULL;
int mem_balloon_is_active=0;
int mem_balloon_should_send_signal=1;
pid_t mem_balloon_reg_task_pid;



/* 
 * To disable the default kernel swapping algorithm so that
 * no anonymous page is swapped after ballooning driver is
 * initialized.
 */ 
void mb_disable_anon_page_swap(void){
    /*
     * Following approaches were explored to disable swapping of anon pages
     *  - Pinning of process pages in RAM 
     *  - Bypassing the swapping mechanism in shrink_page_list
     *  - Changing the scan balance of get_scan_count - This by far seems to be 
     *    the best one, considering it has a very clean code change and just instructs
     *    that no anon page must be swapped. So, kernel won't even try to loop
     *    through anon pages.
     *
     * The vm_swappiness param is not as important as of now, as we are directly 
     * checking in vm_scan.c that if memory ballooning is enabled, set the scan_balance
     * to SCAN_FILE.
     */

    DEBUG_PRINT("Trying to change vm_swappinees to disable swapping\n");
    vm_swappiness = 0; // To Do : Check if a mutex is needed here
    DEBUG_PRINT("vm_swappiness changed to 0\n");
}



/* 
 * Implementation of register ballooning system call.
 */
asmlinkage long __x64_sys_init_ballooning(void){
    DEBUG_PRINT("init_ballooning syscall has been called\n");
    DEBUG_PRINT("PID of calling process is : %d\n", current->pid);

    /* 
     * Save the current process to send the SIGBALLOON signal when needed
     * Also, mark the mem_balloon_is_active flag to enable the check
     * for physical memory.
     *
     * Note to self : current is a macro defined in arch/x86/include/asm/current.h
     * and expands to a function returning pointer (task_struct) to the 
     * current process
    */  
    mem_balloon_reg_task = get_current();
    mem_balloon_reg_task_pid = current->pid;
    mem_balloon_is_active = 1;

    DEBUG_PRINT("Saved the current process identity for sending ballooning signal later\n");
    
    mb_disable_anon_page_swap();

    return 0;
}




