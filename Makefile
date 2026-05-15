CLANG = clang

TARGET = flux

all: $(TARGET).o


$(TARGET).o: src/$(TARGET).c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

clean:
	rm -f *.o
	