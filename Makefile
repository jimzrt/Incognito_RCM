ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>devkitARM")
endif

include $(DEVKITARM)/base_rules

IPL_LOAD_ADDR := 0x40008000

TARGET := Lockpick_RCM
BLVERSION_MAJOR := 1
BLVERSION_MINOR := 0
BUILD := build
OUTPUT := output
SOURCEDIR = source
VPATH = $(dir $(wildcard ./$(SOURCEDIR)/*/)) $(dir $(wildcard ./$(SOURCEDIR)/*/*/))

OBJS = $(addprefix $(BUILD)/$(TARGET)/, \
	start.o \
	main.o \
	keys.o \
	heap.o \
	btn.o \
	clock.o \
	cluster.o \
	fuse.o \
	gpio.o \
	sept.o \
	i2c.o \
	max7762x.o \
	max17050.o \
	mc.o \
	nx_emmc.o \
	sdmmc.o \
	sdmmc_driver.o \
	sdram.o \
	sdram_lp0.o \
	util.o \
	di.o \
	gfx.o \
	pinmux.o \
	pkg1.o \
	pkg2.o \
	se.o \
	tsec.o \
	hw_init.o \
	smmu.o \
	max77620-rtc.o \
)

OBJS += $(addprefix $(BUILD)/$(TARGET)/, \
	lz.o blz.o \
	diskio.o ff.o ffunicode.o ffsystem.o \
)

CUSTOMDEFINES := -DIPL_LOAD_ADDR=$(IPL_LOAD_ADDR)

ARCH := -march=armv4t -mtune=arm7tdmi -mthumb-interwork
CFLAGS = $(ARCH) -O2 -nostdlib -ffunction-sections -fdata-sections -fomit-frame-pointer -std=gnu11 -Wall $(CUSTOMDEFINES)
LDFLAGS = $(ARCH) -nostartfiles -lgcc -Wl,--nmagic,--gc-sections -Xlinker --defsym=IPL_LOAD_ADDR=$(IPL_LOAD_ADDR)

MODULEDIRS := $(wildcard modules/*)

.PHONY: all clean $(MODULEDIRS)

all: $(TARGET).bin
	@echo -n "Payload size is "
	@wc -c < $(OUTPUT)/$(TARGET).bin
	@echo "Max size is 126296 Bytes."

clean:
	@rm -rf $(OBJS)
	@rm -rf $(BUILD)
	@rm -rf $(OUTPUT)

$(MODULEDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

$(TARGET).bin: $(BUILD)/$(TARGET)/$(TARGET).elf $(MODULEDIRS)
	$(OBJCOPY) -S -O binary $< $(OUTPUT)/$@

$(BUILD)/$(TARGET)/$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -T $(SOURCEDIR)/link.ld $^ -o $@

$(BUILD)/$(TARGET)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/$(TARGET)/%.o: %.S
	@mkdir -p "$(BUILD)"
	@mkdir -p "$(BUILD)/$(TARGET)"
	@mkdir -p "$(OUTPUT)"
	$(CC) $(CFLAGS) -c $< -o $@
