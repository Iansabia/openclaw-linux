# Clawd Linux APT Repository

## Setup

Add the repository to your system:

    echo "deb [signed-by=/usr/share/keyrings/clawd-linux.gpg] https://repo.clawd.linux/apt bookworm main" | sudo tee /etc/apt/sources.list.d/clawd-linux.list
    curl -fsSL https://repo.clawd.linux/gpg | sudo gpg --dearmor -o /usr/share/keyrings/clawd-linux.gpg
    sudo apt update

## Install

    sudo apt install clawd-linux
