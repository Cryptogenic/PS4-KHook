PS4SDK	:=	$(PS4SDK)

CC		:=	gcc
AS		:=	gcc
OBJCOPY	:=	objcopy
ODIR	:=	build
SDIR	:=	source
IDIRS	:=	-I$(PS4SDK)/include -I. -Iinclude
LDIRS	:=	-L$(PS4SDK) -L. -Llib
CFLAGS	:=	$(IDIRS) -O0 -fno-builtin -nostartfiles -nostdlib -Wall -m64 -fPIC
SFLAGS	:=	-nostartfiles -nostdlib -fPIC
LFLAGS	:=	$(LDIRS) -Xlinker -T $(PS4SDK)/linker.x -Wl,--build-id=none
CFILES	:=	$(wildcard $(SDIR)/*.c)
SFILES	:=	$(wildcard $(SDIR)/*.s)
OBJS	:=	$(patsubst $(SDIR)/%.c, $(ODIR)/%.o, $(CFILES)) $(patsubst $(SDIR)/%.s, $(ODIR)/%.o, $(SFILES))

LIBS	:=	-lPS4

TARGET = $(shell basename $(CURDIR)).bin

$(TARGET): $(ODIR) $(OBJS)
	$(CC) $(PS4SDK)/crt0.s $(ODIR)/*.o -o $(shell basename $(CURDIR)).elf $(CFLAGS) $(LFLAGS) $(LIBS)
	$(OBJCOPY) -O binary $(shell basename $(CURDIR)).elf $(TARGET)

$(ODIR)/%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(ODIR)/%.o: $(SDIR)/%.s
	$(AS) -c -o $@ $< $(SFLAGS)

$(ODIR):
	@mkdir $@

.PHONY: clean

clean:
	rm -f $(shell basename $(CURDIR)).elf $(TARGET) $(ODIR)/*.o

send:
	socat TCP:$(PS4IP):9020 FILE:$(shell basename $(CURDIR)).bin
