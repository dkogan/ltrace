#ifndef SYSDEPS_LINUX_GNU_EVENTS_H
#define SYSDEPS_LINUX_GNU_EVENTS_H

#include "forward.h"

/* Declarations for event que functions.  */

enum ecb_status {
	ecb_cont, /* The iteration should continue.  */
	ecb_yield, /* The iteration should stop, yielding this
		    * event.  */
	ecb_deque, /* Like ecb_stop, but the event should be removed
		    * from the queue.  */
};

struct Event *each_qd_event(enum ecb_status (*cb)(struct Event *event,
						  void *data), void *data);
void delete_events_for(struct Process * proc);
void enque_event(struct Event *event);

#endif /* SYSDEPS_LINUX_GNU_EVENTS_H */
