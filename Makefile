CONFIGD_SRC += cfgd/configd.c

LIB_SRC += libs/perf.c

CONFIGD_SERVICE_NAME = configd

LIB_NAME = libmwos.a

CC = gcc
AR = ar
AR_ARGS = rcv
CFLAGS += -Iinc/ -Wall -Werror -Wextra -Wshadow -Wno-unused-parameter -fprofile-arcs -ftest-coverage -coverage

CONFIGD_OBJ = $(patsubst %.c, %.o, ${CONFIGD_SRC})
LIB_OBJ = $(patsubst %.c, %.o, ${LIB_SRC})

all: $(LIB_NAME) $(CONFIGD_SERVICE_NAME)

$(CONFIGD_SERVICE_NAME): $(CONFIGD_OBJ)
	${CC} -g $(CONFIGD_OBJ) -lrt -pg -lgcov -coverage -L. -lmwos -lm -o $(CONFIGD_SERVICE_NAME)

$(LIB_NAME): $(LIB_OBJ)
	${AR} ${AR_ARGS} $(LIB_NAME) $(LIB_OBJ)

%.o: %.c
	${CC} $(CFLAGS) -c -o $@ $<


clean:
	rm -rf configd cfgd/*.o cfgd/*.gc* libs/*.o libmwos.a
