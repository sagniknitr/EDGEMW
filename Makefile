CONFIGD_SRC += cfgd/configd.c

CONFIGD_SERVICE_NAME = configd

CC = gcc
AR = ar
CFLAGS += -Iinc/ -Wall -Werror -Wextra -Wshadow -Wno-unused-parameter -fprofile-arcs -ftest-coverage -coverage

CONFIGD_OBJ = $(patsubst %.c, %.o, ${CONFIGD_SRC})

all: $(CONFIGD_SERVICE_NAME)

$(CONFIGD_SERVICE_NAME): $(CONFIGD_OBJ)
	${CC} -g $(CONFIGD_OBJ) -pg -lgcov -coverage -o $(CONFIGD_SERVICE_NAME)

%.o: %.c
	${CC} $(CFLAGS) -c -o $@ $<

