CFLAGS +=  -I. -I.. -I../crypto -I ../injector/include

SRC=$(wildcard *.c)
OBJS=$(SRC:.c=.o)
BIN=degu.pie
all: degu

degu: $(OBJS)
	@$(CC) $(LDFLAGS) $(OBJS) -pie -o ../$(BIN) ../crypto/degucrypto.a ../injector/src/linux/libinjector.a ../ulexec/ulexe.a

%.o : %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -c $<

clean:
	@$(RM) -f *.o 


