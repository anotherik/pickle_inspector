.PHONY: install run docker-run podman-run clean

# Install Python dependencies and ensure 2to3 is available
install:
	@echo "[*] Installing Python dependencies..."
	pip install -r requirements.txt
	@echo "[*] Checking for 2to3..."
	@which 2to3 || (echo "[!] 2to3 not found. Try 'apt install lib2to3' or install Python full distribution." && false)

# Run locally
run:
	python3 cli.py --skip-errors $(TARGET)

# Build and run using Docker
docker-run:
	docker build -t pickle_inspector .
	docker run --rm -v $(PWD):/mnt pickle_inspector /mnt/$(TARGET) --skip-errors

# Build and run using Podman
podman-run:
	podman build -t pickle_inspector .
	podman run --rm -v $(PWD):/mnt pickle_inspector /mnt/$(TARGET) --skip-errors

clean:
	find . -name "*.pyc" -delete
