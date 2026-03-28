FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY auth.py cli.py dual_chain.py node.py evm_gateway.py web_ui.html rwa_ui.html rwa_market_ui.html app_hub_ui.html community_ui.html explorer_ui.html scanner_ui.html passport_ui.html README.md run_tests.sh ./
COPY assets ./assets
COPY tests ./tests
COPY docker ./docker

RUN chmod +x ./docker/node_entrypoint.sh ./docker/gateway_entrypoint.sh ./run_tests.sh

EXPOSE 8000

ENTRYPOINT ["./docker/node_entrypoint.sh"]
