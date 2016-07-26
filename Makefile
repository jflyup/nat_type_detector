CC = gcc

CFLAGS  = -g -Wall

TARGET = nat_type

all: $(TARGET)

$(TARGET): *.c
	$(CC) $(CFLAGS) -o $(TARGET) *.c

clean:
	$(RM) $(TARGET)
