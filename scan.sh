#!/bin/bash
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
B='\033[0;34m'
C='\033[0;36m'
P='\033[0;35m'
N='\033[0m'

pb() {
    clear
    echo -e "${B}"
    echo " ██████╗ ██████╗ ███████╗ █████╗ ████████╗"
    echo "██╔═══██╗██╔══██╗██╔════╝██╔══██╗╚══██╔══╝"
    echo "██║   ██║██████╔╝███████╗███████║   ██║   "
    echo "██║   ██║██╔═══╝ ╚════██║██╔══██║   ██║   "
    echo "╚██████╔╝██║     ███████║██║  ██║   ██║   "
    echo " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   "
    echo -e "${N}Ultimate Security Scanner for WordPress, TG @cybersecurityTemDF - @DRR_R2\n"
}

cd() {
    declare -A t=([curl]="curl" [grep]="grep" [sed]="sed" [awk]="awk" [nmap]="nmap" [openssl]="openssl" [wpscan]="wpscan")
    m=0
    for x in "${!t[@]}"; do
        if ! command -v $x &>/dev/null; then
            echo -e "${R}[-] Missing $x (Install: ${t[$x]})${N}"
            m=1
        fi
    done
    [ $m -eq 1 ] && exit 1
}

wd() {
    echo -e "\n${Y}[+] WordPress Detection & Version Identification${N}"
    vs=("readme.html:Version %{V}" "feed/:<generator>http://wordpress.org/?v=%{V}</generator>" "wp-links-opml.php:generator=\"WordPress/%{V}\"" "wp-admin/admin-ajax.php:admin-ajax-%{V}.js" "wp-includes/js/wp-embed.min.js:embed-%{V}.min.js")
    fv=""
    for s in "${vs[@]}"; do
        IFS=':' read -r u p <<< "$s"
        c=$(curl -sL "${T}/${u}")
        if [[ $c =~ $p ]]; then
            fv=$(echo "${BASH_REMATCH[1]}" | sed 's/[^0-9.]//g')
            [ -n "$fv" ] && break
        fi
    done
    if [ -n "$fv" ]; then
        echo -e "${G}[+] Detected WordPress Version: ${fv}${N}"
        vuln_check "$fv"
    else
        echo -e "${R}[-] Could not determine WordPress version${N}"
    fi
}

vuln_check() {
    echo -e "\n${P}[+] Checking for known vulnerabilities in WordPress $1${N}"
    known_vulns=("4.9.8:2018-8575" "5.0:2019-17671" "5.1.1:2019-17672" "5.2.3:2019-17673" "5.3:2020-28086" "5.4.1:2020-11027" "5.5.3:2020-25283" "5.6:2021-29447" "5.7.2:2021-39273" "5.8.1:2021-39272")
    for vuln in "${known_vulns[@]}"; do
        IFS=':' read -r version cve <<< "$vuln"
        if [[ "$1" == "$version" ]]; then
            echo -e "${R}[!] POTENTIALLY VULNERABLE: Version $version has known CVE-$cve${N}"
        fi
    done
}

ue() {
    echo -e "\n${Y}[+] User Enumeration via REST API${N}"
    u=$(curl -s "${T}/wp-json/wp/v2/users" | grep -Eo '"slug":"[^"]+"' | cut -d\" -f4)
    if [ -n "$u" ]; then 
        echo -e "${R}[!] Discovered users:${N}"
        echo "$u" | while read -r x; do 
            echo -e " - $x"
            id=$(curl -s "${T}/wp-json/wp/v2/users?slug=$x" | grep -Eo '"id":[0-9]+' | cut -d: -f2)
            [ -n "$id" ] && echo -e "   User ID: $id"
        done
    else
        echo -e "${G}[+] No users found via REST API${N}"
    fi
}

fp() {
    echo -e "\n${Y}[+] File Permissions Check${N}"
    sf=("wp-config.php" ".htaccess" "wp-admin/index.php" "wp-login.php" "xmlrpc.php" "wp-config.php~" "wp-config.php.bak" "wp-config.php.save" ".wp-config.php.swp" "wp-config.php.old" "wp-config.php.orig" "wp-config.php.dist")
    for f in "${sf[@]}"; do
        s=$(curl -o /dev/null -s -w "%{http_code}" "${T}/${f}")
        [ "$s" -eq 200 ] && echo -e "${R}[!] Public access to: ${T}/${f}${N}"
    done
}

bf() {
    echo -e "\n${Y}[+] Backup File Detection${N}"
    bf=("*.sql" "*.tar.gz" "*.zip" "*.bak" "wp-content/*.bak" "wp-config.php.bak" "database-backup*.sql" "backup-*.zip" "*.sql.gz" "*.tar" "*.gz" "*.rar" "wp-content/backup-*" "wp-content/uploads/backup-*" "wp-content/backups/*")
    for b in "${bf[@]}"; do
        s=$(curl -o /dev/null -s -w "%{http_code}" "${T}/${b}")
        [ "$s" -eq 200 ] && echo -e "${R}[!] Backup file exposed: ${T}/${b}${N}"
    done
}

pe() {
    echo -e "\n${Y}[+] Plugin Enumeration${N}"
    pl=$(curl -s "${T}/wp-content/plugins/" | grep -Eo "href=\"([^\"]+)\"" | cut -d\" -f2 | grep -v "/$")
    if [ -n "$pl" ]; then
        echo -e "${C}[*] Detected Plugins:${N}"
        echo "$pl" | while read -r p; do
            pn=${p%/}
            echo -e " - ${pn}"
            pv=$(curl -s "${T}/wp-content/plugins/${pn}/readme.txt" | grep -i 'version:' | head -1 | grep -oE '[0-9.]+')
            [ -n "$pv" ] && echo -e "   Version: $pv" && check_plugin_vulns "$pn" "$pv"
        done
    else
        echo -e "${G}[+] No plugins detected${N}"
    fi
}

check_plugin_vulns() {
    known_vuln_plugins=(
        "akismet:4.1.3:2021-24297"
        "contact-form-7:5.3.2:2021-24145"
        "elementor:3.4.7:2021-25067"
        "woocommerce:5.5.2:2021-25068"
        "all-in-one-seo-pack:4.1.5.3:2021-24298"
    )
    for vuln in "${known_vuln_plugins[@]}"; do
        IFS=':' read -r plugin version cve <<< "$vuln"
        if [[ "$1" == "$plugin" && "$2" == "$version" ]]; then
            echo -e "${R}   [!] VULNERABLE: Version $version has known CVE-$cve${N}"
        fi
    done
}

te() {
    echo -e "\n${Y}[+] Theme Enumeration${N}"
    tl=$(curl -s "${T}/wp-content/themes/" | grep -Eo "href=\"([^\"]+)\"" | cut -d\" -f2 | grep -v "/$")
    if [ -n "$tl" ]; then
        echo -e "${C}[*] Detected Themes:${N}"
        echo "$tl" | while read -r x; do
            tn=${x%/}
            echo -e " - $tn"
            v=$(curl -s "${T}/wp-content/themes/${tn}/style.css" | grep -i 'Version:' | grep -oE '[0-9.]+')
            [ -n "$v" ] && echo -e "   Version: $v" && check_theme_vulns "$tn" "$v"
        done
    else
        echo -e "${G}[+] No themes detected${N}"
    fi
}

check_theme_vulns() {
    known_vuln_themes=(
        "twentyseventeen:2.4:2021-24299"
        "twentynineteen:1.8:2021-24300"
        "twentytwenty:1.6:2021-24301"
        "astra:3.6.9:2021-25069"
        "divi:4.9.9:2021-25070"
    )
    for vuln in "${known_vuln_themes[@]}"; do
        IFS=':' read -r theme version cve <<< "$vuln"
        if [[ "$1" == "$theme" && "$2" == "$version" ]]; then
            echo -e "${R}   [!] VULNERABLE: Version $version has known CVE-$cve${N}"
        fi
    done
}

dl() {
    echo -e "\n${Y}[+] Debug Log Check${N}"
    dl=("wp-content/debug.log" "debug.log" "error_log" "wp-content/error_log" "wp-admin/error_log")
    for d in "${dl[@]}"; do
        s=$(curl -o /dev/null -s -w "%{http_code}" "${T}/${d}")
        [ "$s" -eq 200 ] && echo -e "${R}[!] Debug log exposed: ${T}/${d}${N}"
    done
}

ds() {
    echo -e "\n${Y}[+] DNS Security Check${N}"
    dn=$(echo "${T}" | awk -F/ '{print $3}')
    di=$(curl -s "https://dns.google/resolve?name=${dn}&type=A" | grep -oE '"data":"[^"]+"' | cut -d\" -f4)
    if [ -n "$di" ]; then
        echo -e "${C}[*] DNS Records:${N}"
        echo "$di" | while read -r ip; do
            echo -e " - $ip"
            nmap -Pn -p 80,443,8080 --script http-wordpress-enum $ip | grep -v "filtered\|closed"
        done
    else
        echo -e "${R}[-] Failed to retrieve DNS info${N}"
    fi
}

dlc() {
    echo -e "\n${Y}[+] Directory Listing Checks${N}"
    dc=("wp-content/plugins" "wp-content/themes" "wp-content/uploads" "wp-includes" "wp-admin" "wp-content/backups" "wp-content/upgrade" "wp-content/uploads/sites")
    for d in "${dc[@]}"; do
        s=$(curl -s -o /dev/null -w "%{http_code}" "${T}/${d}/")
        if [ "$s" -eq 200 ]; then
            c=$(curl -sL "${T}/${d}/")
            echo "$c" | grep -q "Index of" && echo -e "${R}[!] Directory listing enabled: ${T}/${d}/${N}"
        fi
    done
}

xc() {
    echo -e "\n${Y}[+] XML-RPC Service Check${N}"
    s=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: text/xml" --data "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>" "${T}/xmlrpc.php")
    if [ "$s" -eq 200 ]; then
        echo -e "${R}[!] XML-RPC interface is enabled (potential DDoS/brute force risk)${N}"
        echo -e "${Y}[*] Testing for pingback vulnerability...${N}"
        pingback_test=$(curl -s -X POST -H "Content-Type: text/xml" -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://example.com</string></value></param><param><value><string>${T}/</string></value></param></params></methodCall>" "${T}/xmlrpc.php")
        echo "$pingback_test" | grep -q "faultCode" || echo -e "${R}[!] Pingback may be enabled (potential SSRF risk)${N}"
    else
        echo -e "${G}[+] XML-RPC interface not available${N}"
    fi
}

rc() {
    echo -e "\n${Y}[+] User Registration Check${N}"
    rp=$(curl -sL "${T}/wp-login.php?action=register")
    echo "$rp" | grep -q "Registration confirmation will be emailed to you" && echo -e "${R}[!] User registration is open to the public${N}" || echo -e "${G}[+] User registration is closed${N}"
}

cfi() {
    echo -e "\n${Y}[+] Core File Integrity Check${N}"
    cf=("wp-login.php" "wp-admin/admin-ajax.php" "wp-includes/version.php" "wp-admin/install.php" "wp-includes/js/jquery/jquery.js" "wp-includes/functions.php")
    for f in "${cf[@]}"; do
        curl -sL --head "${T}/${f}" | grep -q "200 OK" || echo -e "${R}[!] Missing core file: ${T}/${f}${N}"
    done
}

sha() {
    echo -e "\n${Y}[+] Server Header Analysis${N}"
    h=$(curl -sI "${T}")
    echo -e "${C}[*] Detected Headers:${N}"
    echo "$h" | grep -E 'Server:|X-Powered-By:|X-Content-Type-Options:|X-Frame-Options:|Content-Security-Policy:'
    echo "$h" | grep -qi "X-Content-Type-Options: nosniff" || echo -e "${R}[!] Missing X-Content-Type-Options header${N}"
    echo "$h" | grep -qi "X-Frame-Options:" || echo -e "${R}[!] Missing X-Frame-Options header (clickjacking risk)${N}"
    echo "$h" | grep -qi "Content-Security-Policy:" || echo -e "${Y}[!] Missing Content-Security-Policy header${N}"
}

hfc() {
    echo -e "\n${Y}[+] Hidden File/Directory Scan${N}"
    hp=(".git/HEAD" ".svn/entries" ".htaccess" ".htpasswd" "wp-config.php.bak" ".env" ".DS_Store" "wp-config.php.save" ".wp-config.php.swp" "wp-config.php.old" "wp-config.php.orig" "wp-config.php.dist" "wp-config.php~" "wp-config.php.backup" "wp-config.php.copy")
    for p in "${hp[@]}"; do
        s=$(curl -s -o /dev/null -w "%{http_code}" "${T}/${p}")
        [ "$s" -eq 200 ] && echo -e "${R}[!] Sensitive file/directory exposed: ${T}/${p}${N}"
    done
}

rta() {
    echo -e "\n${Y}[+] Robots.txt Analysis${N}"
    rt=$(curl -sL "${T}/robots.txt")
    if [ -n "$rt" ]; then
        echo -e "${C}[*] Robots.txt contents:${N}"
        echo "$rt"
        for p in "wp-admin" "wp-includes" "wp-config.php" "wp-login.php" "xmlrpc.php" "wp-content/uploads"; do
            echo "$rt" | grep -qi "Disallow: /${p}" || echo -e "${R}[!] Sensitive path not blocked: ${p}${N}"
        done
    else
        echo -e "${Y}[-] No robots.txt file found${N}"
    fi
}

sc() {
    echo -e "\n${Y}[+] SSL/TLS Configuration Check${N}"
    dn=$(echo "${T}" | awk -F/ '{print $3}')
    echo -e "${C}[*] Testing SSL configuration for: ${dn}${N}"
    openssl s_client -connect "${dn}:443" -servername "${dn}" < /dev/null 2>/dev/null | grep -E 'SSL-Session|Protocol|Cipher'
    echo -e "\n${C}[*] Checking for weak ciphers...${N}"
    nmap --script ssl-enum-ciphers -p 443 $dn | grep -E 'SSLv3|TLSv1.0|TLSv1.1|weak'
}

ad() {
    echo -e "\n${Y}[+] Admin Page Detection${N}"
    ap=$(curl -sL "${T}/wp-admin" | grep -q "wp-admin" && echo "wp-admin")
    [ -n "$ap" ] && echo -e "${R}[!] Admin page detected: ${T}/${ap}${N}" || echo -e "${G}[+] Admin page not detected${N}"
}

ud() {
    echo -e "\n${Y}[+] User Data Enumeration${N}"
    ud=$(curl -sL "${T}/wp-json/wp/v2/users" | grep -Eo '"id":"[^"]+"|"name":"[^"]+"|"slug":"[^"]+"|"email":"[^"]+"')
    [ -n "$ud" ] && echo -e "${R}[!] User data found:${N}" && echo "$ud" | while read -r x; do echo -e " - $x"; done || echo -e "${G}[+] No user data found${N}"
}

pd() {
    echo -e "\n${Y}[+] Post Data Enumeration${N}"
    pd=$(curl -sL "${T}/wp-json/wp/v2/posts" | grep -Eo '"id":"[^"]+"|"title":"[^"]+"|"content":"[^"]+"|"date":"[^"]+"')
    [ -n "$pd" ] && echo -e "${R}[!] Post data found:${N}" && echo "$pd" | while read -r x; do echo -e " - $x"; done || echo -e "${G}[+] No post data found${N}"
}

cd() {
    echo -e "\n${Y}[+] Comment Data Enumeration${N}"
    cd=$(curl -sL "${T}/wp-json/wp/v2/comments" | grep -Eo '"id":"[^"]+"|"author_name":"[^"]+"|"content":"[^"]+"|"date":"[^"]+"')
    [ -n "$cd" ] && echo -e "${R}[!] Comment data found:${N}" && echo "$cd" | while read -r x; do echo -e " - $x"; done || echo -e "${G}[+] No comment data found${N}"
}

wpv() {
    echo -e "\n${Y}[+] WordPress Vulnerability Checks${N}"
    wp_vulns=("wp-admin/js/common.min.js:common-%{V}.min.js" "wp-includes/js/wp-embed.min.js:embed-%{V}.min.js" "wp-includes/js/jquery/jquery.js:jquery-%{V}.js")
    for s in "${wp_vulns[@]}"; do
        IFS=':' read -r u p <<< "$s"
        c=$(curl -sL "${T}/${u}")
        if [[ $c =~ $p ]]; then
            v=$(echo "${BASH_REMATCH[1]}" | sed 's/[^0-9.]//g')
            echo -e "${C}[*] Detected version $v in ${u}${N}"
            check_wp_vulns "$v"
        fi
    done
}

check_wp_vulns() {
    wp_vuln_list=(
        "4.0:2014-9034"
        "4.7.4:2017-9066"
        "4.9.6:2018-12895"
        "5.0.1:2019-6977"
        "5.1.1:2019-9787"
        "5.2.3:2019-17670"
        "5.3:2020-11027"
        "5.4.1:2020-11027"
        "5.5.3:2020-25283"
        "5.6:2021-29447"
    )
    for vuln in "${wp_vuln_list[@]}"; do
        IFS=':' read -r version cve <<< "$vuln"
        if [[ "$1" == "$version" ]]; then
            echo -e "${R}[!] POTENTIALLY VULNERABLE: Version $version has known CVE-$cve${N}"
        fi
    done
}

fs() {
    cd
    pb
    echo -e "${C}[*] Starting Ultimate Security Scan for: ${T}${N}"
    wd
    dlc
    xc
    rc
    ue
    fp
    bf
    pe
    te
    dl
    ds
    cfi
    sha
    hfc
    rta
    sc
    ad
    ud
    pd
    cd
    wpv
    echo -e "\n${G}[+] Ultimate security scan completed${N}"
    echo -e "${Y}[!] Manual verification recommended for complex security issues${N}"
    echo -e "${P}[*] Scan results should be reviewed by a security professional${N}"
}

if [ -z "$1" ]; then
  read -p "ENTER LINK AS (https://domain.com), just WordPress site: " T
  if [ -z "$T" ]; then
    echo -e "${R}No URL provided!${N}"
    exit 1
  fi
else
  T="$1"
fi

fs
