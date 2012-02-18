struct Process;
void output_line(struct Process *proc, char *fmt, ...);
void output_left(enum tof type, struct Process *proc,
		 const char *function_name);
void output_right(enum tof type, struct Process *proc,
		  const char *function_name);
