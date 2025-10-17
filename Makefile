# Determine the operating system
UNAME := $(shell uname)

# Default compiler settings
CC = gcc

# Change compiler based on OS
ifeq ($(UNAME), Darwin)
    CC = clang
endif

ifeq ($(UNAME), FreeBSD)
    CC = clang
endif

# compiler flags:
#  -std=c23	comply with C23
#  -O3		optimize level at 3
#  -g		adds debugging information to the executable file
#  -Wall	turns on most, but not all, compiler warnings
#  -Wextra	additional warnings not covered by -Wall
#  -march=native generate code optimized for the exact CPU doing the build
#  -I.		Add the current directory (.) to the compiler’s include search path

CFLAGS = -std=c23 -O3 -Wall -Wextra -pthread -march=native -I.
RM = rm -f


# the build target executable:
TARGET = review_siftr2_log
default: $(TARGET)

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

.PHONY: depend clean

clean:
	$(RM) $(TARGET)
