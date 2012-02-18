struct Process;
struct library_symbol;
void output_line(struct Process *proc, char *fmt, ...);
void output_left(enum tof type, struct Process *proc,
		 struct library_symbol *libsym);
void output_right(enum tof type, struct Process *proc,
		  struct library_symbol *libsym);
