#project(EDGEMW)

#set(CMAKE_C_FLAGS "-O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -fprofile-arcs -ftest-coverage")
#set(CMAKE_CXX_FLAGS "-std=c++11 -fprofile-arcs -ftest-coverage")

LIB_SRC += common/evtloop/evtloop.c \
		common/algorithms/list.c \
		common/linux/net/socket.c \
		common/logger/edgeos_logger.c \
		common/linux/shmem/shmem.c \

LIB_TEST_SRC += common/tests/test_socket.c

LOGGER_SRC += logsrv/edgeos_logsrv.cpp

LOGGER_TEST_SRC += logsrv/tests/logsrv_test.c

SHM_TRANSPORT_SRC += common/linux/transport/controller.c

INCL_DIR += -I common/evtloop/ \
	-I common/linux/net/ \
	-I remoteLog/ \
	-I common/algorithms/ \
	-I common/logger/ \
	-I common/linux/net/ \
	-I common/linux/shmem/ \
	-I common/linux/transport/

CFLAGS = -O0 -ggdb -g -Wall -Werror -Wextra -Wno-unused-parameter -Wshadow -fPIE -fPIC -fprofile-arcs -ftest-coverage
CXXFLAGS = -std=c++11 -fprofile-arcs -ftest-coverage -g -ggdb

LIB_OBJ = $(patsubst %.c, %.o, ${LIB_SRC})
LIB_TEST_OBJ = $(patsubst %.c, %.o, ${LIB_TEST_SRC})
LOGGER_OBJ = $(patsubst %.cpp, %.opp, ${LOGGER_SRC})
LOGGER_TEST_OBJ = $(patsubst %.c, %.o, ${LOGGER_TEST_SRC})
SHM_TRANSPORT_OBJ = $(patsubst %.c, %.o, ${SHM_TRANSPORT_SRC})

CPP=g++
GCC=gcc
AR=ar

LIB_NAME = libEdgeOS.so
LIB_AR_NAME = libEdgeOS.a
LIB_TEST_NAME=EOSTest
LOGGER_NAME = EdgeOSLogger
LOGGER_TEST_NAME = loggerTest
SHM_TRANSPORT_NAME = shmTransport

all: $(LIB_NAME)	$(LIB_AR_NAME)	$(LOGGER_NAME)	$(LOGGER_TEST_NAME) $(SHM_TRANSPORT_NAME) $(LIB_TEST_NAME)

$(LIB_NAME): $(LIB_OBJ)
	${GCC} -shared $(LIB_OBJ) -lrt -pg -lgcov -o $(LIB_NAME)

$(LIB_AR_NAME): $(LIB_OBJ)
	$(AR) rcv $(LIB_AR_NAME) $(LIB_OBJ)

$(LIB_TEST_NAME): $(LIB_TEST_OBJ)
	${GCC} $(CFLAGS) $(INCL_DIR) $(LIB_TEST_OBJ) $(LIB_AR_NAME) -o $(LIB_TEST_NAME) -pthread -pg -lrt -lgcov

$(LOGGER_NAME): $(LOGGER_OBJ)
	${CPP} $(CXXFLAGS) $(INCL_DIR) $(LOGGER_OBJ) -o $(LOGGER_NAME) -pthread -pg -lrt -lgcov

$(LOGGER_TEST_NAME): $(LOGGER_TEST_OBJ)
	${GCC} $(CFLAGS) $(INCL_DIR) $(LOGGER_TEST_OBJ) $(LIB_AR_NAME) -o $(LOGGER_TEST_NAME) -lrt -pg -lgcov

$(SHM_TRANSPORT_NAME): $(SHM_TRANSPORT_OBJ)
	${GCC} $(CFLAGS) $(INCL_DIR) $(SHM_TRANSPORT_OBJ) $(LIB_AR_NAME) -o $(SHM_TRANSPORT_NAME) -lrt -pg -lgcov

%.o: %.c
	${GCC} $(INCL_DIR) $(CFLAGS) -c -o $@ $<

%.opp: %.cpp
	${GCC} $(INCL_DIR) $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

clean:
	find . -iname *.o | xargs rm -rf
	find . -iname *.opp | xargs rm -rf
	find . -iname *.gcda | xargs rm -rf
	find . -iname *.gcno | xargs rm -rf
	rm $(LIB_NAME) $(LIB_TEST_NAME) $(LOGGER_NAME) $(LOGGER_TEST_NAME) $(SHM_TRANSPORT_NAME) $(LIB_AR_NAME)
