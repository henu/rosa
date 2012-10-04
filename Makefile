CC = g++

#CFLAGS = -g -Wall -O2 -Wpointer-arith -Werror -ansi -pedantic -DENABLE_FILEIO_CACHE
CFLAGS = -g -O3 -DENABLE_FILEIO_CACHE

LIBS = -lhpp `pkg-config --libs hpp`

SRC = \
nodes/datablock.cc \
nodes/file.cc \
nodes/folder.cc \
nodes/node.cc \
nodes/symlink.cc \
archive.cc \
archiver.cc \
fileio.cc \
main.cc

OBJ = $(SRC:%.cc=src/%.o)

all: rosa

clean:
	rm -f $(OBJ) core rosa

rosa: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LIBS)

%.o: %.cc
	$(CC) $(CFLAGS) -c -o $@ $<
