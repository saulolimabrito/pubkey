#!/usr/bin/env bash
set -euo pipefail

SSH_PORT="1157"

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
  sed -i '/^#\?KbdInteractiveAuthentication/d' "$conf"
  sed -i '/^#\?UsePAM/d' "$conf"
  sed -i '/^#\?PubkeyAuthentication/d' "$conf"
  sed -i '/^#\?PermitEmptyPasswords/d' "$conf"
  sed -i '/^#\?Port/d' "$conf"

  cat >> "$conf" <<EOFCONF
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitEmptyPasswords no
PubkeyAuthentication yes
Port ${SSH_PORT}
EOFCONF

  # Em Rocky/Oracle, o instalador pode criar /etc/ssh/sshd_config.d/01-permitrootlogin.conf
  # com PermitRootLogin yes, sobrescrevendo nosso hardening. Este arquivo garante precedência.
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOFHARD
PermitRootLogin prohibit-password
PasswordAuthentication no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitEmptyPasswords no
PubkeyAuthentication yes
Port ${SSH_PORT}
EOFHARD

  echo "Configuração root/chave aplicada no sshd_config e 99-hardening.conf."
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

configure_selinux_ssh_port() {
  if ! command -v getenforce >/dev/null 2>&1 || [[ "$(getenforce)" == "Disabled" ]]; then
    echo "SELinux desativado ou não disponível."
    return 0
  fi

  echo "SELinux ativado. Ajustando para porta ${SSH_PORT}..."
  if ! command -v semanage >/dev/null 2>&1; then
    echo "semanage não encontrado. Instalando policycoreutils-python-utils..."
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y policycoreutils-python-utils
    else
      yum install -y policycoreutils-python-utils
    fi
  fi

  if semanage port -l | grep -Eq "^ssh_port_t[[:space:]]+tcp[[:space:]].*\b${SSH_PORT}\b"; then
    echo "Regra SELinux já existente para ssh_port_t porta ${SSH_PORT}."
  else
    semanage port -a -t ssh_port_t -p tcp "${SSH_PORT}" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "${SSH_PORT}"
    echo "Regra SELinux aplicada para ssh_port_t porta ${SSH_PORT}."
  fi
}

open_firewall_ssh_port() {
  if command -v ufw >/dev/null 2>&1; then
    local ufw_status
    ufw_status="$(ufw status 2>/dev/null | head -n1 || true)"
    if echo "$ufw_status" | grep -qi "Status: active"; then
      ufw allow "${SSH_PORT}/tcp"
      echo "UFW atualizado: ${SSH_PORT}/tcp liberada."
    else
      echo "UFW instalado, mas inativo."
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1; then
    if firewall-cmd --state >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
      firewall-cmd --reload
      echo "firewalld atualizado: ${SSH_PORT}/tcp liberada."
    else
      echo "firewalld instalado, mas inativo."
    fi
  fi
}

validate_sshd_config() {
  if sshd -t; then
    echo "Validação sshd -t: OK"
  else
    echo "Erro de sintaxe no sshd_config. Restaurando backup mais recente..." >&2
    local last_backup
    last_backup="$(ls -1t /etc/ssh/sshd_config.bak.* 2>/dev/null | head -n1 || true)"
    if [[ -n "$last_backup" ]]; then
      cp -f "$last_backup" /etc/ssh/sshd_config
      echo "Backup restaurado: $last_backup" >&2
    fi
    return 1
  fi
}

restart_sshd() {
  if systemctl list-unit-files | grep -qE '^sshd\.service'; then
    systemctl restart sshd
  elif systemctl list-unit-files | grep -qE '^ssh\.service'; then
    systemctl restart ssh
  else
    echo "Não encontrou serviço SSH/sshd para reiniciar."
    return 1
  fi
}

verify_effective_hardening() {
  local effective
  effective="$(sshd -T 2>/dev/null || true)"

  echo "$effective" | grep -q "port ${SSH_PORT}" || { echo "Porta efetiva não é ${SSH_PORT}." >&2; return 1; }
  echo "$effective" | grep -q "passwordauthentication no" || { echo "PasswordAuthentication não está em no." >&2; return 1; }
  echo "$effective" | grep -q "pubkeyauthentication yes" || { echo "PubkeyAuthentication não está em yes." >&2; return 1; }

  if ss -tlnp | grep -qE ":${SSH_PORT}[[:space:]]"; then
    echo "sshd escutando na porta ${SSH_PORT}."
  else
    echo "sshd não está escutando na porta ${SSH_PORT}." >&2
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
    inject_root_public_key "$SSH_KEY"
    open_firewall_ssh_port
    validate_sshd_config
    restart_sshd
    verify_effective_hardening
    echo "Ubuntu $version configurado: SSH root/chave porta ${SSH_PORT}."
    ;;

  rocky|oracle)
    if [[ "$version" != "8" && "$version" != "9" && "$version" != "10" ]]; then
      echo "$distro versão suportada: 8, 9 ou 10. Encontrado: $version"
      exit 1
    fi
    backup_sshd_config
    configure_sshd_root_key_only
    inject_root_public_key "$SSH_KEY"
    configure_selinux_ssh_port
    open_firewall_ssh_port
    validate_sshd_config
    restart_sshd
    verify_effective_hardening
    echo "$distro $version configurado: SSH root/chave porta ${SSH_PORT}."
    ;;
  *)
    echo "Distro não suportada. Suportado: Ubuntu 22/24, Rocky 8/9/10, Oracle 8/9/10."
    exit 1
    ;;
esac

echo "Concluído. Teste SSH na porta ${SSH_PORT} antes de fechar a sessão atual."
