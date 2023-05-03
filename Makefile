# CNI Makefile
#
# Testing the plugin:
#
# source test-env
# make setup
# make add P=ipams1
# make del P=ipams1
# make clean

CNITOOL = cnitool
SUDO = sudo -E

PLUGIN=test
ifdef P
	PLUGIN := $(P)
endif

build:
	./build_linux.sh

# Create a testing namespace
setup:
	$(SUDO) ip netns add testing

add:
	$(SUDO) $(CNITOOL) add $(PLUGIN) /var/run/netns/testing

check:
	$(SUDO) $(CNITOOL) check $(PLUGIN) /var/run/netns/testing

test:
	$(SUDO) ip -n testing addr
	$(SUDO) ip netns exec testing ping -c 1 4.2.2.2

del:
	$(SUDO) $(CNITOOL) del $(PLUGIN) /var/run/netns/testing

clean:
	$(SUDO) ip netns del testing
	$(SUDO) rm -rf /var/lib/cni/networks/* /tmp/ipams.log /tmp/ptp.log
