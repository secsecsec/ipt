#
#  Makefile
#	By Benjamin Kittridge. Copyright (C) 2013, All rights reserved.
#
#

###################################################
# Options

NAME =		ipt
VERSION =	1.0

BIN_PATH =	bin
BIN =		ipt

SRC_PATH =	src
SRC =		$(patsubst %.cpp,%.o,$(wildcard ${SRC_PATH}/*.cpp)) \
		$(patsubst %.cpp,%.o,$(wildcard ${SRC_PATH}/*/*.cpp)) \
		$(patsubst %.cpp,%.o,$(wildcard ${SRC_PATH}/*/*/*.cpp))

LINK_ARG =	-pthread
COMPILE_ARG =	-g -iquote ${SRC_PATH} -Wall

###################################################
# Programs

ECHO =		echo
GCC =		g++
RM =		rm
MKDIR =		mkdir

###################################################
# Build

all: info build

info:
	@${ECHO} "BUILDING: ${NAME}"

-include $(SRC:.o=.d)

.SUFFIXES:
.SUFFIXES: .cpp .so .o
.cpp.o:
	@${ECHO} "COMPILE:  $<"
	@${GCC} -MD -c $< -o $@ ${COMPILE_ARG}

build: ${SRC}
	@${MKDIR} -p ${BIN_PATH}
	@${ECHO} "LINK:     ${BIN_PATH}/${BIN}"
	@${GCC} -o ${BIN_PATH}/${BIN} ${SRC} ${LINK_ARG}
	@${ECHO}
	
clean:
	@${RM} -f ${BIN_PATH}/${BIN} ${SRC} $(SRC:.o=.d)
