CFLAGS += -Wall -fPIC -I.

ULEXE=$(wildcard *.c)
ULEXE_OBJS=$(ULEXE:.c=.o)

all: ulexe.a

ulexe.a: $(ULEXE_OBJS)
	@$(AR) rcs ulexe.a $(ULEXE_OBJS)

%.o : %.c
	@echo CC $< 
	@$(CC) $(CFLAGS) -c $<

clean:
	@$(RM) *.o
	@$(RM) ulexe.a $(ULEXE_OBJS)

