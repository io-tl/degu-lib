CFLAGS += -Wall -fPIC -I. 

CRYPTO=$(wildcard *.c)
CRYPTO_OBJS=$(CRYPTO:.c=.o)

all: degucrypto.a

degucrypto.a: $(CRYPTO_OBJS)
	@$(AR) rcs degucrypto.a $(CRYPTO_OBJS)

%.o : %.c
	@echo CC $< 
	@$(CC) $(CFLAGS) -c $<

clean:
	@$(RM) *.o
	@$(RM) degucrypto.a $(INJECTOR_OBJS)

