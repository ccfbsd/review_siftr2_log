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

# Common flags (used by all builds)
COMMON_CFLAGS = -std=c23 -Wall -Wextra -pthread -I.

# Release / optimized flags (default)
RELEASE_CFLAGS = -O3 -march=native -msse4.1 -mavx2 -mfma -DNDEBUG

# Debug flags
DEBUG_CFLAGS = -O0 -g3 -fno-omit-frame-pointer -DDEBUG

# Default build mode
BUILD ?= release

# Select flags based on build mode
ifeq ($(BUILD),debug)
    CFLAGS = $(COMMON_CFLAGS) $(DEBUG_CFLAGS)
else
    CFLAGS = $(COMMON_CFLAGS) $(RELEASE_CFLAGS)
endif

# OS-specific overrides
ifeq ($(UNAME), Darwin)
    CC = clang
    RELEASE_CFLAGS = -O3 -march=native -DNDEBUG
endif

ifeq ($(UNAME), FreeBSD)
    CC = clang
endif

RM = rm -rf

# the build target executable:
TARGET = review_siftr2_log
default: $(TARGET)

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

.PHONY: clean debug release

debug:
	$(MAKE) BUILD=debug

release:
	$(MAKE) BUILD=release

clean:
	$(RM) $(TARGET)
	[ ! -d $(TARGET).dSYM ] || $(RM) $(TARGET).dSYM
