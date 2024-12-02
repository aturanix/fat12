.PHONY: compile clean

CFLAGS = -O3 -Wall -Wextra -std=gnu99
LDFLAGS =
LDLIBS =

SRCFILES1 = main.c filesystem.c
OBJFILES1 = $(SRCFILES1:.c=.o)
TARGET1 = fileSystemOper

SRCFILES2 = main-mkfs.c
OBJFILES2 = $(SRCFILES2:.c=.o)
TARGET2 = makeFileSystem

compile: $(TARGET1) $(TARGET2)

$(TARGET1): $(OBJFILES1)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET1) $(OBJFILES1) $(LDLIBS)

$(TARGET2): $(OBJFILES2)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET2) $(OBJFILES2) $(LDLIBS)

clean:
	rm $(TARGET1) $(OBJFILES1) $(TARGET2) $(OBJFILES2)
