# Determine the operating system
UNAME := $(shell uname)

# compiler flags:
#  -std=c23	comply with C23
#  -O3		optimize level at 3
#  -g		adds debugging information to the executable file
#  -Wall	turns on most, but not all, compiler warnings
#  -Wextra	additional warnings not covered by -Wall
#  -march=native generate code optimized for the exact CPU doing the build
#  -I.		Add the current directory (.) to the compiler’s include search path
#  -msse4.1	Enable SSE4.1 intrinsics
#  -mavx2	Enable AVX2 intrinsics
#  -mfma	Enable FMA instructions

# Default compiler settings
CC = gcc
CFLAGS = -std=c23 -O3 -msse4.1 -mavx2 -mfma -Wall -Wextra -pthread -march=native -I.

# Change compiler based on OS
ifeq ($(UNAME), Darwin)
    CC = clang
    CFLAGS = -std=c23 -O3 -Wall -Wextra -pthread -march=native -I.
endif

ifeq ($(UNAME), FreeBSD)
    CC = clang
endif

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
