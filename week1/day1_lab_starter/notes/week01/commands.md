# Day 1 – Commands Log

## Install Docker Engine + Compose (Debian/Ubuntu/Kali)
```bash
sudo apt-get remove -y docker docker-engine docker.io containerd runc || true
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") \
  $(. /etc/os-release; echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

docker --version
docker compose version
docker buildx version
sudo usermod -aG docker $USER
```

## Repo init
```bash
git init
cp .env.example .env
git add .
git commit -m "Day1: baseline lab skeleton + telemetry"
```

## Bring up stack
```bash
docker compose -f infra/docker-compose.yml --env-file .env up -d
docker compose -f infra/docker-compose.yml ps
curl -sf http://localhost/health && echo "proxy OK"
```

## Grafana
- URL: http://localhost/grafana
- Login from `.env`
- Verify **Loki** datasource + "Day1 Logs (Basic)" dashboard

## Nmap sweep
```bash
mkdir -p notes/week01/day1/nmap
sudo nmap -sn 172.18.0.0/16 -oA notes/week01/day1/nmap/lab-sweep
sudo nmap -sC -sV -O -T3 -p- -oA notes/week01/day1/nmap/lab-deep 172.18.0.2 172.18.0.3 172.18.0.4
xsltproc notes/week01/day1/nmap/lab-deep.xml -o notes/week01/day1/nmap/lab-deep.html
```
