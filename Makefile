.PHONY: certs up down logs build clean

certs:
	@mkdir -p certs
	@bash scripts/gen-certs.sh

build:
	docker compose build

up: certs
	@mkdir -p logs
	docker compose up -d
	@echo ""
	@echo "Proxy ready at localhost:3128"
	@echo "Install certs/squid-ca.pem on monitored endpoints."

down:
	docker compose down

logs:
	docker compose logs -f icap-server

clean:
	docker compose down -v
	rm -rf certs logs
