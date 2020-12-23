rwildcard = $(foreach d, $(wildcard $1*), $(filter $(subst *, %, $2), $d) $(call rwildcard, $d/, $2))

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif

include $(DEVKITARM)/base_rules

################################################################################

IPL_LOAD_ADDR := 0x40003000
LPVERSION_MAJOR := 0
LPVERSION_MINOR := 6
LPVERSION_BUGFX := 8

################################################################################

TARGET := Incognito_RCM
BUILDDIR := build
OUTPUTDIR := output
SOURCEDIR = source
BDKDIR := bdk
BDKINC := -I./$(BDKDIR)
VPATH = $(dir ./$(SOURCEDIR)/) $(dir $(wildcard ./$(SOURCEDIR)/*/)) $(dir $(wildcard ./$(SOURCEDIR)/*/*/))
VPATH += $(dir $(wildcard ./$(BDKDIR)/)) $(dir $(wildcard ./$(BDKDIR)/*/)) $(dir $(wildcard ./$(BDKDIR)/*/*/))

OBJS =	$(patsubst $(SOURCEDIR)/%.S, $(BUILDDIR)/$(TARGET)/%.o, \
		$(patsubst $(SOURCEDIR)/%.c, $(BUILDDIR)/$(TARGET)/%.o, \
		$(call rwildcard, $(SOURCEDIR), *.S *.c)))
OBJS +=	$(patsubst $(BDKDIR)/%.S, $(BUILDDIR)/$(TARGET)/%.o, \
		$(patsubst $(BDKDIR)/%.c, $(BUILDDIR)/$(TARGET)/%.o, \
		$(call rwildcard, $(BDKDIR), *.S *.c)))

GFX_INC   := '"../$(SOURCEDIR)/gfx/gfx.h"'
FFCFG_INC := '"../$(SOURCEDIR)/libs/fatfs/ffconf.h"'

################################################################################

CUSTOMDEFINES := -DIPL_LOAD_ADDR=$(IPL_LOAD_ADDR)
CUSTOMDEFINES += -DLP_VER_MJ=$(LPVERSION_MAJOR) -DLP_VER_MN=$(LPVERSION_MINOR) -DLP_VER_BF=$(LPVERSION_BUGFX)
CUSTOMDEFINES += -DGFX_INC=$(GFX_INC) -DFFCFG_INC=$(FFCFG_INC)

ARCH := -march=armv4t -mtune=arm7tdmi -mthumb -mthumb-interwork
CFLAGS = $(ARCH) -O2 -nostdlib -ffunction-sections -fno-inline -fdata-sections -fomit-frame-pointer -std=gnu11 -Wall $(CUSTOMDEFINES)
LDFLAGS = $(ARCH) -nostartfiles -lgcc -Wl,--allow-multiple-definition,--nmagic,--gc-sections -Xlinker --defsym=IPL_LOAD_ADDR=$(IPL_LOAD_ADDR)

################################################################################

.PHONY: all clean

all: $(OUTPUTDIR)/$(TARGET).bin

clean:
	@rm -rf $(BUILDDIR)
	@rm -rf $(OUTPUTDIR)

$(OUTPUTDIR)/$(TARGET).bin: $(BUILDDIR)/$(TARGET)/$(TARGET).elf
	@mkdir -p "$(@D)"
	$(OBJCOPY) -S -O binary $< $@
	@echo -n "Payload size is "
	$(eval BIN_SIZE = $(shell wc -c < $(OUTPUTDIR)/$(TARGET).bin))
	@echo $(BIN_SIZE)
	@echo "Max size is 126296 Bytes."
	@if [ ${BIN_SIZE} -gt 126296 ]; then echo "\e[1;33mPayload size exceeds limit!\e[0m"; fi

$(BUILDDIR)/$(TARGET)/$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -T $(SOURCEDIR)/link.ld $^ -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(SOURCEDIR)/%.c
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) $(BDKINC) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(SOURCEDIR)/%.S
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(BDKDIR)/%.c
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) $(BDKINC) -c $< -o $@

$(BUILDDIR)/$(TARGET)/%.o: $(BDKDIR)/%.S
	@mkdir -p "$(@D)"
	$(CC) $(CFLAGS) -c $< -o $@
