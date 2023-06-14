KERNEL_PATH := /lib/modules/$(shell uname -r)/build
CURRENT_DIR := $(shell pwd)
MODULE_NAME := ma_der

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs += main.o mdr_packet_info.o mdr_flow.o mdr_flow_table.o

all:
	make -C $(KERNEL_PATH) M=$(CURRENT_DIR) modules

clean:
	make -C $(KERNEL_PATH) M=$(CURRENT_DIR) clean