#!/bin/bash
# Script developed by muneer461
# Kali Linux tools installation script

# Function to display a banner with animation
show_banner() {
    clear
    neon_banner="
    ███    ██ ███████  ██████  ███    ██ 
    ████   ██ ██      ██    ██ ████   ██ 
    ██ ██  ██ █████   ██    ██ ██ ██  ██ 
    ██  ██ ██ ██      ██    ██ ██  ██ ██ 
    ██   ████ ███████  ██████  ██   ████ 
    "
    printf "%s\n" "$neon_banner"
    sleep 0.1
    printf "\nThank you for using this tool!\n"
    sleep 0.5
    printf "N E O N\n"
    sleep 0.5
}

# Function to install Kali Linux packages with animation
cd
install_packages() {
    printf "\n➣ Installing packages...\n"
    sleep 0.5

    packages=(
        "git" "proot" "nano" "apache2" "bash" "python2" "php" "ruby" "wget" "nmap"
        "nginx" "zip" "unzip" "hydra" "python3" "curl" "aircrack-ng" "beef-xss" "clang"
        "metasploit-framework" "net-tools" "wireshark" "john" "sqlmap" "openvpn" "nikto"
        "dirbuster" "sqlninja" "tcpdump" "ettercap-text-only" "burpsuite" "hashcat" 
        "reaver" "dsniff" "lynis" "openvas" "zaproxy" "theharvester" "scapy" 
        "mitmproxy" "maltego" "tshark" "hping3" "ngrep" "lft" "joomscan" "yersinia"
        "patator" "wapiti" "skipfish" "whatweb" "thc-ssl-dos" "rainbowcrack" "arp-scan"
        "wpscan" "tor" "network-manager" "synaptic" "snapd" "gnome-software"
    )

    # Remove duplicates and sort the list
    packages=($(printf "%s\n" "${packages[@]}" | awk '!seen[$0]++' | sort))

    # Installation commands with animation
    sudo apt-get update -y && printf "Updating repositories...\n" && sleep 0.5
    sudo apt-get upgrade -y && printf "Upgrading packages...\n" && sleep 0.5
    sudo apt-get install -y "${packages[@]}" && printf "Installing packages...\n" && sleep 0.5
    sudo pip install requests netaddr argparse mechanize bs4 wafw00f
    sudo apt install -y snapd
    sudo systemctl enable --now snapd apparmor
    sudo snap install snap-store hello-world || echo "Error installing snap packages. Proceeding without them."

    printf "Packages installed successfully.\n"
}

# Function to clone GitHub repositories with animation
clone_github_repos() {
    printf "\n➣ Cloning GitHub repositories...\n"
    sleep 0.5

    repos=(
        "https://github.com/noob-hackers/tunnel"
        "https://github.com/hax4us/termuxblack"
        "https://github.com/muneer461/mr.mn461"
        "https://github.com/muneer461/sms"
        "https://github.com/ignitetch/advphishing"
        "https://github.com/thewhiteh4t/seeker"
        "https://github.com/ha3mrx/ddos-attack"
        "https://github.com/ha3mrx/instabrute"
        "https://github.com/ha3mrx/facebook-cracker"
        "https://github.com/hangetzzu/saycheese"
        "https://github.com/noob-hackers/hacklock"
        "https://github.com/ranginang67/darkfly-tool"
        "https://github.com/gameye98/santet-online"
        "https://github.com/noob-hackers/p-gen"
        "https://github.com/kuburan/txtool"
        "https://github.com/sherlock-project/sherlock"
        "https://github.com/htr-tech/track-ip"
        "https://github.com/htr-tech/zphisher"
        "https://github.com/Ign0r3dH4x0r/Xweapon"
        "https://github.com/jofpin/trape"
        "https://github.com/aboul3la/Sublist3r"
        "https://github.com/Greyjedix/Profil3r"
        "https://github.com/p1ngul1n0/blackbird"
        "https://github.com/p4pentest/SuperEnum"
        "https://github.com/palahsu/DDoS-Ripper"
        "https://github.com/qeeqbox/social-analyzer"
        "https://github.com/LandGrey/pydictor"
        "https://github.com/s0md3v/Photon"
        "https://github.com/digininja/CeWL"
        "https://github.com/bahatiphill/BillCipher"
        "https://github.com/m4ll0k/SecretFinder"
        "https://github.com/darkoperator/dnsrecon"
        "https://github.com/owerdogan/whoami-project"
    )

    # Remove duplicates and sort the list
    repos=($(printf "%s\n" "${repos[@]}" | awk '!seen[$0]++' | sort))

    for repo in "${repos[@]}"; do
        if [ -d "$(basename "$repo" .git)" ]; then
            printf "Skipping %s, directory already exists.\n" "$repo"
        else
            printf "Cloning repository: %s\n" "$repo"
            git clone "$repo" || printf "Failed to clone repository: %s\n" "$repo"
        fi
    done

    printf "Repositories cloned successfully.\n"
}

# Main execution
main() {
    show_banner
    install_packages
    clone_github_repos
    printf "Installation and setup complete.\n"
}

# Execute the main function
main
