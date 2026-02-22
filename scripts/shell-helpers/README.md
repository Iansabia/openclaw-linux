# ClawDock <!-- omit in toc -->

Stop typing `docker-compose` commands. Just type `kelpdock-start`.

Inspired by Simon Willison's [Running Kelp in Docker](https://til.simonwillison.net/llms/kelp-docker).

- [Quickstart](#quickstart)
- [Available Commands](#available-commands)
  - [Basic Operations](#basic-operations)
  - [Container Access](#container-access)
  - [Web UI \& Devices](#web-ui--devices)
  - [Setup \& Configuration](#setup--configuration)
  - [Maintenance](#maintenance)
  - [Utilities](#utilities)
- [Common Workflows](#common-workflows)
  - [Check Status and Logs](#check-status-and-logs)
  - [Set Up WhatsApp Bot](#set-up-whatsapp-bot)
  - [Troubleshooting Device Pairing](#troubleshooting-device-pairing)
  - [Fix Token Mismatch Issues](#fix-token-mismatch-issues)
  - [Permission Denied](#permission-denied)
- [Requirements](#requirements)

## Quickstart

**Install:**

```bash
mkdir -p ~/.kelpdock && curl -sL https://raw.githubusercontent.com/kelp/kelp/main/scripts/shell-helpers/kelpdock-helpers.sh -o ~/.kelpdock/kelpdock-helpers.sh
```

```bash
echo 'source ~/.kelpdock/kelpdock-helpers.sh' >> ~/.zshrc && source ~/.zshrc
```

**See what you get:**

```bash
kelpdock-help
```

On first command, ClawDock auto-detects your Kelp directory:

- Checks common paths (`~/kelp`, `~/workspace/kelp`, etc.)
- If found, asks you to confirm
- Saves to `~/.kelpdock/config`

**First time setup:**

```bash
kelpdock-start
```

```bash
kelpdock-fix-token
```

```bash
kelpdock-dashboard
```

If you see "pairing required":

```bash
kelpdock-devices
```

And approve the request for the specific device:

```bash
kelpdock-approve <request-id>
```

## Available Commands

### Basic Operations

| Command            | Description                     |
| ------------------ | ------------------------------- |
| `kelpdock-start`   | Start the gateway               |
| `kelpdock-stop`    | Stop the gateway                |
| `kelpdock-restart` | Restart the gateway             |
| `kelpdock-status`  | Check container status          |
| `kelpdock-logs`    | View live logs (follows output) |

### Container Access

| Command                   | Description                                    |
| ------------------------- | ---------------------------------------------- |
| `kelpdock-shell`          | Interactive shell inside the gateway container |
| `kelpdock-cli <command>`  | Run Kelp CLI commands                      |
| `kelpdock-exec <command>` | Execute arbitrary commands in the container    |

### Web UI & Devices

| Command                 | Description                                |
| ----------------------- | ------------------------------------------ |
| `kelpdock-dashboard`    | Open web UI in browser with authentication |
| `kelpdock-devices`      | List device pairing requests               |
| `kelpdock-approve <id>` | Approve a device pairing request           |

### Setup & Configuration

| Command              | Description                                       |
| -------------------- | ------------------------------------------------- |
| `kelpdock-fix-token` | Configure gateway authentication token (run once) |

### Maintenance

| Command            | Description                                      |
| ------------------ | ------------------------------------------------ |
| `kelpdock-rebuild` | Rebuild the Docker image                         |
| `kelpdock-clean`   | Remove all containers and volumes (destructive!) |

### Utilities

| Command              | Description                               |
| -------------------- | ----------------------------------------- |
| `kelpdock-health`    | Run gateway health check                  |
| `kelpdock-token`     | Display the gateway authentication token  |
| `kelpdock-cd`        | Jump to the Kelp project directory    |
| `kelpdock-config`    | Open the Kelp config directory        |
| `kelpdock-workspace` | Open the workspace directory              |
| `kelpdock-help`      | Show all available commands with examples |

## Common Workflows

### Check Status and Logs

**Restart the gateway:**

```bash
kelpdock-restart
```

**Check container status:**

```bash
kelpdock-status
```

**View live logs:**

```bash
kelpdock-logs
```

### Set Up WhatsApp Bot

**Shell into the container:**

```bash
kelpdock-shell
```

**Inside the container, login to WhatsApp:**

```bash
kelp channels login --channel whatsapp --verbose
```

Scan the QR code with WhatsApp on your phone.

**Verify connection:**

```bash
kelp status
```

### Troubleshooting Device Pairing

**Check for pending pairing requests:**

```bash
kelpdock-devices
```

**Copy the Request ID from the "Pending" table, then approve:**

```bash
kelpdock-approve <request-id>
```

Then refresh your browser.

### Fix Token Mismatch Issues

If you see "gateway token mismatch" errors:

```bash
kelpdock-fix-token
```

This will:

1. Read the token from your `.env` file
2. Configure it in the Kelp config
3. Restart the gateway
4. Verify the configuration

### Permission Denied

**Ensure Docker is running and you have permission:**

```bash
docker ps
```

## Requirements

- Docker and Docker Compose installed
- Bash or Zsh shell
- Kelp project (from `docker-setup.sh`)

## Development

**Test with fresh config (mimics first-time install):**

```bash
unset KELPOCK_DIR && rm -f ~/.kelpdock/config && source scripts/shell-helpers/kelpdock-helpers.sh
```

Then run any command to trigger auto-detect:

```bash
kelpdock-start
```
