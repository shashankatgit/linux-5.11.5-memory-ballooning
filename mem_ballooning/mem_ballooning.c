#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/swap.h> // For vm_swappiness

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
    DEBUG_PRINT("Attempting to change vm_swappiness to 0\n");
    vm_swappiness = 0; // To Do : Check if a mutex is needed here
    DEBUG_PRINT("vm_swappiness changed to 0\n");
}


/* 
 * Implementation of register ballooning system call.
*/
asmlinkage long __x64_sys_init_ballooning(void){
    // struct kernel_siginfo info;
    // int ret;

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

    DEBUG_PRINT("Saving the current process identity for sending ballooning signal later\n");
    // DEBUG_PRINT("Sending a test signal to the process\n");
    

    // memset(&info, 0, sizeof(struct kernel_siginfo));
    // info.si_signo = SIG_BALLOON;
    // info.si_code = SI_KERNEL;
    // info.si_int = 1234;

    /*
        Note to self : send_sig_info moved to linux/sched/signal.h since 4.11 
        and 4.20 has changed siginfo to kernel_siginfo
    */

    /* send the signal to the process */
    // ret = send_sig_info(SIG_BALLOON, &info, mem_balloon_reg_task);    

    // if (ret < 0) {
	// 	DEBUG_PRINT("error sending SIGBALLOON signal\n");
	// 	return ret;
	// }

    mb_disable_anon_page_swap();

    return 0;
}




