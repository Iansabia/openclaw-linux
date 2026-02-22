#!/usr/bin/env bash
# ClawDock - Docker helpers for Kelp
# Inspired by Simon Willison's "Running Kelp in Docker"
# https://til.simonwillison.net/llms/kelp-docker
#
# Installation:
#   mkdir -p ~/.kelpdock && curl -sL https://raw.githubusercontent.com/kelp/kelp/main/scripts/shell-helpers/kelpdock-helpers.sh -o ~/.kelpdock/kelpdock-helpers.sh
#   echo 'source ~/.kelpdock/kelpdock-helpers.sh' >> ~/.zshrc
#
# Usage:
#   kelpdock-help    # Show all available commands

# =============================================================================
# Colors
# =============================================================================
_CLR_RESET='\033[0m'
_CLR_BOLD='\033[1m'
_CLR_DIM='\033[2m'
_CLR_GREEN='\033[0;32m'
_CLR_YELLOW='\033[1;33m'
_CLR_BLUE='\033[0;34m'
_CLR_MAGENTA='\033[0;35m'
_CLR_CYAN='\033[0;36m'
_CLR_RED='\033[0;31m'

# Styled command output (green + bold)
_clr_cmd() {
  echo -e "${_CLR_GREEN}${_CLR_BOLD}$1${_CLR_RESET}"
}

# Inline command for use in sentences
_cmd() {
  echo "${_CLR_GREEN}${_CLR_BOLD}$1${_CLR_RESET}"
}

# =============================================================================
# Config
# =============================================================================
KELPOCK_CONFIG="${HOME}/.kelpdock/config"

# Common paths to check for Kelp
KELPOCK_COMMON_PATHS=(
  "${HOME}/kelp"
  "${HOME}/workspace/kelp"
  "${HOME}/projects/kelp"
  "${HOME}/dev/kelp"
  "${HOME}/code/kelp"
  "${HOME}/src/kelp"
)

_kelpdock_filter_warnings() {
  grep -v "^WARN\|^time="
}

_kelpdock_trim_quotes() {
  local value="$1"
  value="${value#\"}"
  value="${value%\"}"
  printf "%s" "$value"
}

_kelpdock_read_config_dir() {
  if [[ ! -f "$KELPOCK_CONFIG" ]]; then
    return 1
  fi
  local raw
  raw=$(sed -n 's/^KELPOCK_DIR=//p' "$KELPOCK_CONFIG" | head -n 1)
  if [[ -z "$raw" ]]; then
    return 1
  fi
  _kelpdock_trim_quotes "$raw"
}

# Ensure KELPOCK_DIR is set and valid
_kelpdock_ensure_dir() {
  # Already set and valid?
  if [[ -n "$KELPOCK_DIR" && -f "${KELPOCK_DIR}/docker-compose.yml" ]]; then
    return 0
  fi

  # Try loading from config
  local config_dir
  config_dir=$(_kelpdock_read_config_dir)
  if [[ -n "$config_dir" && -f "${config_dir}/docker-compose.yml" ]]; then
    KELPOCK_DIR="$config_dir"
    return 0
  fi

  # Auto-detect from common paths
  local found_path=""
  for path in "${KELPOCK_COMMON_PATHS[@]}"; do
    if [[ -f "${path}/docker-compose.yml" ]]; then
      found_path="$path"
      break
    fi
  done

  if [[ -n "$found_path" ]]; then
    echo ""
    echo "🦞 Found Kelp at: $found_path"
    echo -n "   Use this location? [Y/n] "
    read -r response
    if [[ "$response" =~ ^[Nn] ]]; then
      echo ""
      echo "Set KELPOCK_DIR manually:"
      echo "  export KELPOCK_DIR=/path/to/kelp"
      return 1
    fi
    KELPOCK_DIR="$found_path"
  else
    echo ""
    echo "❌ Kelp not found in common locations."
    echo ""
    echo "Clone it first:"
    echo ""
    echo "  git clone https://github.com/Iansabia/kelp-os.git ~/kelp"
    echo "  cd ~/kelp && ./docker-setup.sh"
    echo ""
    echo "Or set KELPOCK_DIR if it's elsewhere:"
    echo ""
    echo "  export KELPOCK_DIR=/path/to/kelp"
    echo ""
    return 1
  fi

  # Save to config
  if [[ ! -d "${HOME}/.kelpdock" ]]; then
    /bin/mkdir -p "${HOME}/.kelpdock"
  fi
  echo "KELPOCK_DIR=\"$KELPOCK_DIR\"" > "$KELPOCK_CONFIG"
  echo "✅ Saved to $KELPOCK_CONFIG"
  echo ""
  return 0
}

# Wrapper to run docker compose commands
_kelpdock_compose() {
  _kelpdock_ensure_dir || return 1
  local compose_args=(-f "${KELPOCK_DIR}/docker-compose.yml")
  if [[ -f "${KELPOCK_DIR}/docker-compose.extra.yml" ]]; then
    compose_args+=(-f "${KELPOCK_DIR}/docker-compose.extra.yml")
  fi
  command docker compose "${compose_args[@]}" "$@"
}

_kelpdock_read_env_token() {
  _kelpdock_ensure_dir || return 1
  if [[ ! -f "${KELPOCK_DIR}/.env" ]]; then
    return 1
  fi
  local raw
  raw=$(sed -n 's/^KELP_GATEWAY_TOKEN=//p' "${KELPOCK_DIR}/.env" | head -n 1)
  if [[ -z "$raw" ]]; then
    return 1
  fi
  _kelpdock_trim_quotes "$raw"
}

# Basic Operations
kelpdock-start() {
  _kelpdock_compose up -d kelp-gateway
}

kelpdock-stop() {
  _kelpdock_compose down
}

kelpdock-restart() {
  _kelpdock_compose restart kelp-gateway
}

kelpdock-logs() {
  _kelpdock_compose logs -f kelp-gateway
}

kelpdock-status() {
  _kelpdock_compose ps
}

# Navigation
kelpdock-cd() {
  _kelpdock_ensure_dir || return 1
  cd "${KELPOCK_DIR}"
}

kelpdock-config() {
  cd ~/.kelp
}

kelpdock-workspace() {
  cd ~/.kelp/workspace
}

# Container Access
kelpdock-shell() {
  _kelpdock_compose exec kelp-gateway \
    bash -c 'echo "alias kelp=\"./kelp.mjs\"" > /tmp/.bashrc_kelp && bash --rcfile /tmp/.bashrc_kelp'
}

kelpdock-exec() {
  _kelpdock_compose exec kelp-gateway "$@"
}

kelpdock-cli() {
  _kelpdock_compose run --rm kelp-cli "$@"
}

# Maintenance
kelpdock-rebuild() {
  _kelpdock_compose build kelp-gateway
}

kelpdock-clean() {
  _kelpdock_compose down -v --remove-orphans
}

# Health check
kelpdock-health() {
  _kelpdock_ensure_dir || return 1
  local token
  token=$(_kelpdock_read_env_token)
  if [[ -z "$token" ]]; then
    echo "❌ Error: Could not find gateway token"
    echo "   Check: ${KELPOCK_DIR}/.env"
    return 1
  fi
  _kelpdock_compose exec -e "KELP_GATEWAY_TOKEN=$token" kelp-gateway \
    node dist/index.js health
}

# Show gateway token
kelpdock-token() {
  _kelpdock_read_env_token
}

# Fix token configuration (run this once after setup)
kelpdock-fix-token() {
  _kelpdock_ensure_dir || return 1

  echo "🔧 Configuring gateway token..."
  local token
  token=$(kelpdock-token)
  if [[ -z "$token" ]]; then
    echo "❌ Error: Could not find gateway token"
    echo "   Check: ${KELPOCK_DIR}/.env"
    return 1
  fi

  echo "📝 Setting token: ${token:0:20}..."

  _kelpdock_compose exec -e "TOKEN=$token" kelp-gateway \
    bash -c './kelp.mjs config set gateway.remote.token "$TOKEN" && ./kelp.mjs config set gateway.auth.token "$TOKEN"' 2>&1 | _kelpdock_filter_warnings

  echo "🔍 Verifying token was saved..."
  local saved_token
  saved_token=$(_kelpdock_compose exec kelp-gateway \
    bash -c "./kelp.mjs config get gateway.remote.token 2>/dev/null" 2>&1 | _kelpdock_filter_warnings | tr -d '\r\n' | head -c 64)

  if [[ "$saved_token" == "$token" ]]; then
    echo "✅ Token saved correctly!"
  else
    echo "⚠️  Token mismatch detected"
    echo "   Expected: ${token:0:20}..."
    echo "   Got: ${saved_token:0:20}..."
  fi

  echo "🔄 Restarting gateway..."
  _kelpdock_compose restart kelp-gateway 2>&1 | _kelpdock_filter_warnings

  echo "⏳ Waiting for gateway to start..."
  sleep 5

  echo "✅ Configuration complete!"
  echo -e "   Try: $(_cmd kelpdock-devices)"
}

# Open dashboard in browser
kelpdock-dashboard() {
  _kelpdock_ensure_dir || return 1

  echo "🦞 Getting dashboard URL..."
  local output exit_status url
  output=$(_kelpdock_compose run --rm kelp-cli dashboard --no-open 2>&1)
  exit_status=$?
  url=$(printf "%s\n" "$output" | _kelpdock_filter_warnings | grep -o 'http[s]\?://[^[:space:]]*' | head -n 1)
  if [[ $exit_status -ne 0 ]]; then
    echo "❌ Failed to get dashboard URL"
    echo -e "   Try restarting: $(_cmd kelpdock-restart)"
    return 1
  fi

  if [[ -n "$url" ]]; then
    echo "✅ Opening: $url"
    open "$url" 2>/dev/null || xdg-open "$url" 2>/dev/null || echo "   Please open manually: $url"
    echo ""
    echo -e "${_CLR_CYAN}💡 If you see 'pairing required' error:${_CLR_RESET}"
    echo -e "   1. Run: $(_cmd kelpdock-devices)"
    echo "   2. Copy the Request ID from the Pending table"
    echo -e "   3. Run: $(_cmd 'kelpdock-approve <request-id>')"
  else
    echo "❌ Failed to get dashboard URL"
    echo -e "   Try restarting: $(_cmd kelpdock-restart)"
  fi
}

# List device pairings
kelpdock-devices() {
  _kelpdock_ensure_dir || return 1

  echo "🔍 Checking device pairings..."
  local output exit_status
  output=$(_kelpdock_compose exec kelp-gateway node dist/index.js devices list 2>&1)
  exit_status=$?
  printf "%s\n" "$output" | _kelpdock_filter_warnings
  if [ $exit_status -ne 0 ]; then
    echo ""
    echo -e "${_CLR_CYAN}💡 If you see token errors above:${_CLR_RESET}"
    echo -e "   1. Verify token is set: $(_cmd kelpdock-token)"
    echo "   2. Try manual config inside container:"
    echo -e "      $(_cmd kelpdock-shell)"
    echo -e "      $(_cmd 'kelp config get gateway.remote.token')"
    return 1
  fi

  echo ""
  echo -e "${_CLR_CYAN}💡 To approve a pairing request:${_CLR_RESET}"
  echo -e "   $(_cmd 'kelpdock-approve <request-id>')"
}

# Approve device pairing request
kelpdock-approve() {
  _kelpdock_ensure_dir || return 1

  if [[ -z "$1" ]]; then
    echo -e "❌ Usage: $(_cmd 'kelpdock-approve <request-id>')"
    echo ""
    echo -e "${_CLR_CYAN}💡 How to approve a device:${_CLR_RESET}"
    echo -e "   1. Run: $(_cmd kelpdock-devices)"
    echo "   2. Find the Request ID in the Pending table (long UUID)"
    echo -e "   3. Run: $(_cmd 'kelpdock-approve <that-request-id>')"
    echo ""
    echo "Example:"
    echo -e "   $(_cmd 'kelpdock-approve 6f9db1bd-a1cc-4d3f-b643-2c195262464e')"
    return 1
  fi

  echo "✅ Approving device: $1"
  _kelpdock_compose exec kelp-gateway \
    node dist/index.js devices approve "$1" 2>&1 | _kelpdock_filter_warnings

  echo ""
  echo "✅ Device approved! Refresh your browser."
}

# Show all available kelpdock helper commands
kelpdock-help() {
  echo -e "\n${_CLR_BOLD}${_CLR_CYAN}🦞 ClawDock - Docker Helpers for Kelp${_CLR_RESET}\n"

  echo -e "${_CLR_BOLD}${_CLR_MAGENTA}⚡ Basic Operations${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-start)       ${_CLR_DIM}Start the gateway${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-stop)        ${_CLR_DIM}Stop the gateway${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-restart)     ${_CLR_DIM}Restart the gateway${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-status)      ${_CLR_DIM}Check container status${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-logs)        ${_CLR_DIM}View live logs (follows)${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_MAGENTA}🐚 Container Access${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-shell)       ${_CLR_DIM}Shell into container (kelp alias ready)${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-cli)         ${_CLR_DIM}Run CLI commands (e.g., kelpdock-cli status)${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-exec) ${_CLR_CYAN}<cmd>${_CLR_RESET}  ${_CLR_DIM}Execute command in gateway container${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_MAGENTA}🌐 Web UI & Devices${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-dashboard)   ${_CLR_DIM}Open web UI in browser ${_CLR_CYAN}(auto-guides you)${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-devices)     ${_CLR_DIM}List device pairings ${_CLR_CYAN}(auto-guides you)${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-approve) ${_CLR_CYAN}<id>${_CLR_RESET} ${_CLR_DIM}Approve device pairing ${_CLR_CYAN}(with examples)${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_MAGENTA}⚙️  Setup & Configuration${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-fix-token)   ${_CLR_DIM}Configure gateway token ${_CLR_CYAN}(run once)${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_MAGENTA}🔧 Maintenance${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-rebuild)     ${_CLR_DIM}Rebuild Docker image${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-clean)       ${_CLR_RED}⚠️  Remove containers & volumes (nuclear)${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_MAGENTA}🛠️  Utilities${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-health)      ${_CLR_DIM}Run health check${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-token)       ${_CLR_DIM}Show gateway auth token${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-cd)          ${_CLR_DIM}Jump to kelp project directory${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-config)      ${_CLR_DIM}Open config directory (~/.kelp)${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-workspace)   ${_CLR_DIM}Open workspace directory${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${_CLR_RESET}"
  echo -e "${_CLR_BOLD}${_CLR_GREEN}🚀 First Time Setup${_CLR_RESET}"
  echo -e "${_CLR_CYAN}  1.${_CLR_RESET} $(_cmd kelpdock-start)          ${_CLR_DIM}# Start the gateway${_CLR_RESET}"
  echo -e "${_CLR_CYAN}  2.${_CLR_RESET} $(_cmd kelpdock-fix-token)      ${_CLR_DIM}# Configure token${_CLR_RESET}"
  echo -e "${_CLR_CYAN}  3.${_CLR_RESET} $(_cmd kelpdock-dashboard)      ${_CLR_DIM}# Open web UI${_CLR_RESET}"
  echo -e "${_CLR_CYAN}  4.${_CLR_RESET} $(_cmd kelpdock-devices)        ${_CLR_DIM}# If pairing needed${_CLR_RESET}"
  echo -e "${_CLR_CYAN}  5.${_CLR_RESET} $(_cmd kelpdock-approve) ${_CLR_CYAN}<id>${_CLR_RESET}   ${_CLR_DIM}# Approve pairing${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_GREEN}💬 WhatsApp Setup${_CLR_RESET}"
  echo -e "  $(_cmd kelpdock-shell)"
  echo -e "    ${_CLR_BLUE}>${_CLR_RESET} $(_cmd 'kelp channels login --channel whatsapp')"
  echo -e "    ${_CLR_BLUE}>${_CLR_RESET} $(_cmd 'kelp status')"
  echo ""

  echo -e "${_CLR_BOLD}${_CLR_CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${_CLR_RESET}"
  echo ""

  echo -e "${_CLR_CYAN}💡 All commands guide you through next steps!${_CLR_RESET}"
  echo -e "${_CLR_BLUE}📚 Docs: ${_CLR_RESET}${_CLR_CYAN}https://docs.kelp.ai${_CLR_RESET}"
  echo ""
}
