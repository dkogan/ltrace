#include <pthread.h>

extern void print (char *);

#define	PRINT_LOOP	10

void *
th_main (void *arg)
{
  int i;
  for (i=0; i<PRINT_LOOP; i++)
    print (arg);
}

int
main ()
{
  pthread_t thread1;
  pthread_t thread2;
  pthread_t thread3;
  pthread_create (&thread1, NULL, th_main, "aaa");
  pthread_create (&thread2, NULL, th_main, "bbb");
  pthread_create (&thread3, NULL, th_main, "ccc");
  pthread_join (thread1, NULL);
  pthread_join (thread2, NULL);
  pthread_join (thread3, NULL);
  return 0;
}

