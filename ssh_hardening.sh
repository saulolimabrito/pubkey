#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Execute como root (sudo)."
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Não foi possível detectar a distro. /etc/os-release não encontrado."
  exit 1
fi

. /etc/os-release

distro=${ID,,}
version=${VERSION_ID%%.*}

echo "Distro detectada: $distro $version"

ensure_wget() {
  if command -v wget >/dev/null 2>&1; then
    return 0
  fi
  echo "wget não encontrado. Instalando..."
  if [[ "$distro" == "ubuntu" ]]; then
    apt-get update -y
    apt-get install -y wget
  elif [[ "$distro" == "rocky" || "$distro" == "oracle" ]]; then
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y wget
    else
      yum install -y wget
    fi
  else
    echo "Distribuição desconhecida para instalar wget. Instale manualmente." >&2
    exit 1
  fi
  echo "wget instalado."
}

# chave pública fixa (injeção automática)
SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAt28s9uINW3pGQrht7LL6JaBh0PR6TzIH+g9gcd/t4vUAY5j+wbXi6F4LLsIWu/TSt+2P+HL4S5pQStZe4AkncV5KdCENNKwyyhn4raHYktiWK5F9RBDBxVmUReJFgfb2gV+3YwIARz7B+kE9SCFgHsYwelembYjOh8SIJlKMdtr8B6zDQnNZtC5JAC1joQB03btR/AKL/tch3K70eGRWq0mtcNl37g72e6GRAIiJrTY06gM3kilGYXtAPoWJouXYPX/UptFEgx6LBufLtdLzr+VWvW/T3X5hcgCTgnIf9fgoAD1hXqLKqz8+rfrKPAuuJ3oFnw/xi63/oVBjXMSSRw== saulo.b@dimenoc.com"
if [[ -n "${SSH_PUBLIC_KEY:-}" ]]; then
  SSH_KEY="$SSH_PUBLIC_KEY"
fi

ensure_wget

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key-file)
      shift
      if [[ -z "${1:-}" ]]; then
        echo "Uso: --key-file <arquivo>" >&2
        exit 1
      fi
      SSH_KEY="$(<"$1")"
      shift
      ;;
    --key)
      shift
      SSH_KEY="$1"
      shift
      ;;
    *)
      echo "Parâmetro desconhecido: $1" >&2
      exit 1
      ;;
  esac
done

backup_sshd_config() {
  cp -p /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)
  echo "Backup /etc/ssh/sshd_config criado."
}

configure_sshd_root_key_only() {
  local conf="/etc/ssh/sshd_config"
  sed -i '/^#\?PermitRootLogin/d' "$conf"
  sed -i '/^#\?PasswordAuthentication/d' "$conf"
  sed -i '/^#\?ChallengeResponseAuthentication/d' "$conf"
  sed -i '/^#\?UsePAM/d' "$conf"
  sed -i '/^#\?PubkeyAuthentication/d' "$conf"

  cat >> "$conf" <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PermitEmptyPasswords no
PubkeyAuthentication yes
EOF
  echo "Configuração root/chave aplicada no sshd_config."
}

inject_root_public_key() {
  local key="$1"
  local auth="/root/.ssh/authorized_keys"
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh

  if [[ -z "$key" ]]; then
    echo "Nenhuma chave pública fornecida para injeção." >&2
    return 1
  fi

  if grep -Fxq "$key" "$auth" 2>/dev/null; then
    echo "Chave já presente em $auth"
    return 0
  fi

  echo "$key" >> "$auth"
  chmod 600 "$auth"
  chown root:root /root/.ssh /root/.ssh/authorized_keys
  echo "Chave pública injetada em $auth"
}

configure_sshd_port() {
  local port="$1"
  local conf="/etc/ssh/sshd_config"
  sed -i '/^#\?Port/d' "$conf"
  echo "Port $port" >> "$conf"
  echo "Porta SSH configurada: $port"
}

reload_sshd() {
  if systemctl list-unit-files | grep -qE '^sshd\.service'; then
    systemctl reload sshd || systemctl restart sshd
  elif systemctl list-unit-files | grep -qE '^ssh\.service'; then
    systemctl reload ssh || systemctl restart ssh
  else
    echo "Não encontrou serviço SSH/sshd para reiniciar."
    return 1
  fi
}

case "$distro" in
  ubuntu)
    if [[ "$version" != "22" && "$version" != "24" ]]; then
      echo "Ubuntu versão suportada: 22 ou 24. Encontrado: $version"
      exit 1
    fi
    backup_sshd_config
    configure_sshd_root_key_only
    if ! inject_root_public_key "$SSH_KEY"; then
      echo "Falha ao injetar chave root. Informe SSH_PUBLIC_KEY ou --key-file." >&2
      exit 1
    fi
    configure_sshd_port 1157
    reload_sshd
    echo "Ubuntu $version configurado: SSH root/chave porta 1157."
    ;;

  rocky|oracle)
    if [[ "$version" != "8" && "$version" != "9" && "$version" != "10" ]]; then
      echo "$distro versão suportada: 8, 9 ou 10. Encontrado: $version"
      exit 1
    fi
    backup_sshd_config
    configure_sshd_root_key_only
    if ! inject_root_public_key "$SSH_KEY"; then
      echo "Falha ao injetar chave root. Informe SSH_PUBLIC_KEY ou --key-file." >&2
      exit 1
    fi
    configure_sshd_port 1157
    if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce)" != "Disabled" ]]; then
      echo "SELinux ativado. Ajustando para porta 1157..."
      if command -v semanage >/dev/null 2>&1; then
        semanage port -a -t ssh_port_t -p tcp 1157 2>/dev/null || true
        semanage port -m -t ssh_port_t -p tcp 1157
        echo "Regra SELinux aplicada para ssh_port_t porta 1157."
      else
        echo "semanage não encontrado. Instale policycoreutils-python-utils e execute semanage manualmente."
      fi
    else
      echo "SELinux desativado ou não disponível."
    fi
    reload_sshd
    echo "$distro $version configurado: SSH root/chave porta 1157."
    ;;
  *)
    echo "Distro não suportada. Suportado: Ubuntu 22/24, Rocky 8/9/10, Oracle 8/9/10."
    exit 1
    ;;
esac

echo "Concluído. Verifique /etc/ssh/sshd_config e teste SSH antes de fechar a sessão atual."
