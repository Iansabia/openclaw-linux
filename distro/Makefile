.PHONY: iso clean

LIVE_BUILD_DIR = live-build

iso:
	cd $(LIVE_BUILD_DIR) && \
	lb config \
		--distribution bookworm \
		--archive-areas "main contrib non-free non-free-firmware" \
		--architectures amd64 \
		--binary-images iso-hybrid \
		--iso-application "Kelp Linux" \
		--iso-volume "KELP_LINUX" \
		--bootappend-live "boot=live quiet splash" \
		--memtest none && \
	sudo lb build

clean:
	cd $(LIVE_BUILD_DIR) && sudo lb clean
