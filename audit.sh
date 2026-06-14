#!/bin/bash

# Generated with help of deepseek

#!/usr/bin/env bash
#
# code_audit.sh - Fast code audit script
# Usage: ./audit.sh [--dict dictionary.txt] [--target path] [--help]
#
# Checks:
#  1. Only visible ASCII + tab, LF, CR, space allowed.
#  2. Custom dictionary (political slogans / forbidden phrases).
#  3. Extra quality & security checks:
#      - trailing whitespace
#      - lines > 120 chars
#      - missing final newline
#      - BOM (UTF-8 byte order mark)
#      - CRLF line endings
#      - hardcoded secrets (API keys, tokens, private keys)
#      - dangerous functions (eval, exec, system, popen, backticks, $())
#      - TODO/FIXME comments
#      - shebang but missing executable bit
#      - empty files
#      - mixed line endings (CR without LF)
#

set -euo pipefail
set -x

# Defaults
TARGET="."
DICT_FILE=""
VERBOSE=false
IGNORE_LIST=""

# Colors for output (optional)
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

usage() {
    cat <<EOF
Usage: $0 [--dict dictionary.txt] [--target path] [--verbose] [--help]

Options:
  --dict FILE     File with forbidden phrases (one per line, case‑insensitive)
  --target PATH   File or directory to audit (default: current directory)
  --ignore        File with suppressed warnings (line-separated)
  --verbose       Show extra info (e.g., skipped binary files)
  --help          Show this help

Examples:
  $0 --dict banned.txt --target ./src
  $0 --target script.sh
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dict)
            DICT_FILE="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --ignore)
            IGNORE_LIST=$(sort "$2" | uniq | awk 'NF')  # sort and remove empty lines
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# --- Helper functions --------------------------------------------------

# Check if a file is a text file (MIME type text/*)
is_text_file() {
    local file="$1"
    local mime
    mime=$(file -b --mime-type "$file" 2>/dev/null)
    [[ "$mime" == text/* ]]
}

# Check for allowed characters (visible ASCII + tab, LF, CR, space)
check_allowed_chars() {
    local file="$1"
    # Perl: line by line, print file:line if any forbidden char appears
    # Forbidden: anything not 0x09,0x0A,0x0D,0x20-0x7E
    perl -ne '
        if (/[^\x09\x0A\x0D\x20-\x7E]/) {
            print "$ARGV:$.: $_";
        }
    ' "$file" 2>/dev/null
}

# Check against custom dictionary (fixed strings, case‑insensitive)
check_dictionary() {
    local file="$1"
    if [[ -f "$DICT_FILE" ]]; then
        grep -Hn -i -F -f "$DICT_FILE" "$file" 2>/dev/null || true
    fi
}

# Extra checks
check_trailing_whitespace() {
    grep --with-filename --line-number '[[:space:]]$' "$file" 2>/dev/null || true
}

check_long_lines() {
    awk -v max=120 'length($0) > max { print FILENAME ":" NR ": line too long (" length($0) " chars)" }' "$file"
}

check_missing_newline() {
    # If last char is not newline (0x0A), report
    if [[ -s "$file" ]]; then
        local lastchar
        lastchar=$(tail -c1 "$file" | od -An -tx1 | tr -d ' \n')
        if [[ "$lastchar" != "0a" ]]; then
            echo "$file:1: missing final newline"
        fi
    fi
}

check_bom() {
    local bom
    bom=$(head -c3 "$file" | od -An -tx1 | tr -d ' \n')
    if [[ "$bom" == "efbbbf" ]]; then
        echo "$file:1: UTF-8 BOM marker found (not recommended)"
    fi
}

check_crlf() {
    if grep -q '\r' "$file"; then
        echo "$file:1: contains CRLF (Windows) line endings"
    fi
}

check_mixed_line_endings() {
    # CR without LF (rare, but can break tools)
    if grep -q '\r' "$file" && ! grep -q '\r' "$file"; then
        echo "$file:1: contains bare carriage return (CR) characters"
    fi
}

check_hardcoded_secrets() {
    # Common secret patterns (simple regex)
    patterns=(
        'password\s*=\s*["'"'"'][^"'"'"']*["'"'"']'
        'api_key\s*=\s*["'"'"'][^"'"'"']*["'"'"']'
        'secret\s*=\s*["'"'"'][^"'"'"']*["'"'"']'
        'token\s*=\s*["'"'"'][^"'"'"']*["'"'"']'
        '-----BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----'
        'AKIA[0-9A-Z]{16}'                     # AWS access key
        '-----BEGIN\s+PGP\s+PRIVATE\s+KEY-----'
        # TODO: ssh keys and such
    )
    for pat in "${patterns[@]}"; do
        grep -Hn -E "$pat" "$file" 2>/dev/null || true
    done
}

check_dangerous_functions() {
    # Shell / system calls that may be dangerous if not handled carefully
    dangerous=(
        'eval\s*\('
        'exec\s*\('
        '\$\('          # command substitution (shell)
        '`[^`]*`'       # backticks
        'system\s*\('
        'popen\s*\('
        'subprocess\.'
        'os\.system\s*\('
        'Runtime\.exec\s*\('   # Java
        'ProcessBuilder'
    )
    for pat in "${dangerous[@]}"; do
        grep -Hn -E "$pat" "$file" 2>/dev/null || true
    done
}

check_todo_fixme() {
    grep -Hn -i -E '(todo|fixme)' "$file" 2>/dev/null || true
}

check_shebang_executable() {
    if head -1 "$file" | grep -q '^#!'; then
        if [[ ! -x "$file" ]]; then
            echo "$file:1: shebang present but file is not executable"
        fi
    fi
}

check_empty_file() {
    if [[ ! -s "$file" ]]; then
        echo "$file:1: empty file"
    fi
}

check_vim_file() {
    grep -Hn -f "vim_patterns.grep" "$file" 2>/dev/null || true
}

check_py_file() {
    # TODO: dangerous functions specific to python
    # - relative imports
    :
}

check_sh_file() {
    # TODO:
    # - su, sudo, chmod, mount, umount
    # - /dev
    :
}

without_ignored() {
    if [[ -z $IGNORE_LIST ]]; then
        return 0
    fi
    local s=$(echo "$1" | sort)
    comm --check-order -1 <(echo "$s") <(echo "$IGNORE_LIST")
}

do_report() {
    local message="$1"
    local check_output=$(without_ignored "$2")
    # local check_output="$2"
    local color="${3:-}"
    echo -en "${message} check..."
    if [[ -n "$check_output" ]]; then
        echo -e "${color}FAIL${NC}"
        local trimmed=$(echo "$check_output" | head -n10)
        local total_lines=$(echo "$check_output" | wc -l)
        echo "$trimmed"
        if [[ total_lines -gt 10 ]]; then 
            echo -e "${color}TRIMMED (total $total_lines lines)${NC}"
        fi
        echo -e "${color}===================${NC}"
    else
        echo -e "${GREEN}OK${NC}"
    fi
}

# --- Main audit loop ---------------------------------------------------

audit_file() {
    local file="$1"

    # Skip symlinks (optional, feel free to remove)
    if [[ -L "$file" ]]; then
        return
    fi

    # Skip non‑text files (fast heuristic)
    if ! is_text_file "$file"; then
        $VERBOSE && echo "Skipping non‑text: $file" >&2
        return
    fi

    # 1. Allowed characters (only visible ASCII + tab, LF, CR, space)
    local bad_chars=$(check_allowed_chars "$file")
    do_report "[ALLOWED_CHARS]" "$bad_chars" "${RED}"

    # 2. Dictionary check (political slogans / forbidden phrases)
    if [[ -f "$DICT_FILE" ]]; then
        local dict_hits=$(check_dictionary "$file")
        do_report "[DICTIONARY]" "$dict_hits" "${RED}"
    fi

    # 3. vim-specific checks
    if [ "${file: -4}" = ".vim" -o "${file: -5}" = "vimrc" ]; then
        local vim_check=$(check_vim_file "$file")
        do_report "[VIM-SPECIFIC]" "${vim_check}" "${RED}"
    fi

    # 4. Extra checks (quality & security)
    local trail=$(check_trailing_whitespace "$file")
    do_report "[TRAILING WHITESPACE]" "$trail" "${YELLOW}"

    local long=$(check_long_lines "$file")
    do_report "[LINE TOO LONG]" "${long}" "${YELLOW}"

    local newline=$(check_missing_newline "$file")
    do_report "[MISSING FINAL NEWLINE]" "${newline}" "${YELLOW}"

    local bom=$(check_bom "$file")
    do_report "[UTF-8 BOM]" "${bom}" "${YELLOW}"

    local crlf=$(check_crlf "$file")
    do_report "[CRLF LINE ENDINGS]" "${crlf}" "${YELLOW}"

    local mixed=$(check_mixed_line_endings "$file")
    do_report "[MIXED LINE ENDINGS]" "${mixed}" "${YELLOW}"

    local secrets=$(check_hardcoded_secrets "$file")
    do_report "[POSSIBLE HARDCODED SECRET]" "${secrets}" "${RED}"

    local dangerous=$(check_dangerous_functions "$file")
    do_report "[DANGEROUS FUNCTION CALL]" "${dangerous}" "${RED}"

    local todo=$(check_todo_fixme "$file")
    do_report "[TODO/FIXME]" "${todo}" "${YELLOW}"

    local shebang=$(check_shebang_executable "$file")
    do_report "[SHEBANG EXECUTABLE]" "${shebang}" "${YELLOW}"

    local empty=$(check_empty_file "$file")
    do_report "[EMPTY FILE]" "${empty}" "${YELLOW}"

    # TODO: 
    # - custom checkers for filetypes
    # - c++ function dictionary
    # - vim modeline
    # - file:line ignore list, supplied via command line argument
    # - [hard] incorporate existing dictionaries:
    #   - https://github.com/johnsaigle/scary-strings
    #   - https://github.com/danielmiessler/SecLists
    #   - https://github.com/swisskyrepo/PayloadsAllTheThings
}

# --- Collect files and run audit ---------------------------------------

do_audit() {
    for f in $(find "$1" -type f); do
        audit_file "$f"
    done
}

# TODO: run in bwrap with readonly rights
# TODO: links & devices - detect and report
do_audit "$TARGET"

echo -e "${GREEN}Audit completed.${NC}"
