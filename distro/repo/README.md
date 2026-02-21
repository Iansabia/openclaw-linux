# Kelp Linux APT Repository

## Setup

Add the repository to your system:

    echo "deb [signed-by=/usr/share/keyrings/kelp-linux.gpg] https://repo.kelp.linux/apt bookworm main" | sudo tee /etc/apt/sources.list.d/kelp-linux.list
    curl -fsSL https://repo.kelp.linux/gpg | sudo gpg --dearmor -o /usr/share/keyrings/kelp-linux.gpg
    sudo apt update

## Install

    sudo apt install kelp-linux
