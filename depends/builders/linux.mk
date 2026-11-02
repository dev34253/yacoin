build_linux_SHA256SUM = sha256sum
build_linux_DOWNLOAD = curl --location --fail --connect-timeout $(DOWNLOAD_CONNECT_TIMEOUT) --retry $(DOWNLOAD_RETRIES) --speed-limit $(DOWNLOAD_SPEED_LIMIT) --speed-time $(DOWNLOAD_SPEED_TIME) -o
