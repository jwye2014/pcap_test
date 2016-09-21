OBJECTS = pkc.o

TARGET = pkc
$(TARGET) : $(OBJECTS)
	gcc -o $(TARGET) $(OBJECTS) -lpcap -lnet

pkc.o : pkc.c
