/* Use 1GB memory */
#define TOTAL_MEMORY_SIZE	(1UL * 800 * 1024 * 1024)

#include <sys/time.h>

/*
 * Test-case 1
 */
long test_case_1(int *ptr, long len)
{
	long i, sum = 0;
	int iter, tmp;
	struct timeval ts_start, ts_end;
	unsigned long long ts_tot_exec_us;

	for (iter = 0; iter < 50; iter++) {
		printf("\n\n\n-------------%dth iteration of testcase 1--------------\n\n", iter);
		gettimeofday(&ts_start, NULL);
		for (i = 0; i < len/2; i++) {
			ptr[i] = ptr[i] + 1;
		}
		gettimeofday(&ts_end, NULL);
		ts_tot_exec_us = 1000000 * (ts_end.tv_sec - ts_start.tv_sec) +
	    	(ts_end.tv_usec - ts_start.tv_usec);
		printf("\n\n\n--------------------T1 : %dth iteration took : %.3f seconds-----------\n\n",iter, (double)ts_tot_exec_us/1000000);	
	}
	return sum;
}


/*
 * main entry point for testing use-cases.
 */
void test_case_main(int *ptr, unsigned long size)
{
	long len;
	struct timeval ts_start, ts_end;
	unsigned long long ts_tot_exec_us;

	len = size / sizeof(int);

	gettimeofday(&ts_start, NULL);
	test_case_1(ptr, len);
	gettimeofday(&ts_end, NULL);
	ts_tot_exec_us = 1000000 * (ts_end.tv_sec - ts_start.tv_sec) +
	    (ts_end.tv_usec - ts_start.tv_usec);
	printf("Total execution time for testcase 1 : %.3f seconds\n\n", (double)ts_tot_exec_us/1000000);
}
