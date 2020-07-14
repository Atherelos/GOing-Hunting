#!/bin/bash
#
#Disclaimer, this is a work in progress! 
#
#Addtionally, with a large target the wayback data can get pretty large. Tested against a company operating a bug bounty program and it got up to about 16gb. 
#
#A few dependencies are needed to run this tool. 
#
#1.) GO should be installed (Guide to installing GO on Kali "https://tzusec.com/how-to-install-golang-in-kali-linux/") 
#
#2.) Tool list 
#	1.) Assetfinder -- "https://github.com/tomnomnom/assetfinder"
#	2.) Httprobe -- "https://github.com/tomnomnom/assetfinder"
#	3.) Waybackurls -- "https://github.com/tomnomnom/assetfinder"
#	4.) Subjack -- "https://github.com/haccer/subjack"
#	5.) Nmap (should be installed if running from Kali, if not) -- "https://nmap.org/download.html"
#	6.) GoWitness -- "https://github.com/sensepost/gowitness"

echo "[+] Script Started"
date 

url=$1
scopeFile=$2 

echo "[+] Checking GO tools installed..."

assetFinder=$(which assetfinder)
httProbe=$(which httprobe)
subJack=$(which subjack)
waybackUrls=$(which waybackurls)
goWitness=$(which gowitness)


if 
	[ -z "$assetFinder" ]; then
		echo "[-] assetfinder is not installed"
else
		echo "[+] assetfinder is installed"
		which assetfinder
fi

if 
	[ -z "$httProbe" ]; then
		echo "[-] httprobe is not installed"
else
		echo "[+] httprobe is installed"
		which httprobe
fi

if 
	[ -z "$subJack" ]; then
		echo "[-] subjack is not installed"
else
		echo "[+] subjack is installed"
		which subjack
fi

if 
	[ -z "$waybackUrls" ]; then
		echo "[-] waybackurls is not installed"
else
		echo "[+] waybackurls is installed"
		which waybackurls
fi

if 
	[ -z "$goWitness" ]; then
		echo "[-] gowitness is not installed"
else
		echo "[+] gowitness is installed"
		which gowitness
fi

if [ ! -d "$url" ];then
	mkdir $url
fi
if [ ! -d "$url/recon" ];then
	mkdir $url/recon
fi
if [ ! -d "$url/recon/scans" ];then
	mkdir $url/recon/scans
fi
if [ ! -d "$url/recon/httprobe" ];then
	mkdir $url/recon/httprobe
fi
if [ ! -d "$url/recon/potential_takeovers" ];then
	mkdir $url/recon/potential_takeovers
fi
if [ ! -d "$url/recon/gowitness" ];then
	mkdir $url/recon/gowitness
fi
if [ ! -d "$url/recon/wayback" ];then
	mkdir $url/recon/wayback
fi
if [ ! -d "$url/recon/wayback/params" ];then
	mkdir $url/recon/wayback/params
fi
if [ ! -d "$url/recon/wayback/extensions" ];then
	mkdir $url/recon/wayback/extensions
fi
if [ ! -f "$url/recon/httprobe/alive.txt" ];then
	touch $url/recon/httprobe/alive.txt
fi
if [ ! -f "$url/recon/final.txt" ];then
	touch $url/recon/final.txt
fi

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
rm $url/recon/assets.txt

echo "[+] Probing for alive domains on 443..."
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/a.txt
sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive.txt
rm $url/recon/httprobe/a.txt

echo "[+] Probing for alive domains on 8443..."
cat $url/recon/final.txt | sort -u | httprobe -s -p https:8443 | sed 's/https\?:\/\///' | tr -d ':8443' >> $url/recon/httprobe/a.txt
sort -u $url/recon/httprobe/a.txt >> $url/recon/httprobe/alive.txt
rm $url/recon/httprobe/a.txt


if [ -f "$scopeFile" ];then 
	echo "[+] Creating comparison file..."
	for line in $(cat $url/recon/httprobe/alive.txt );do 
	nslookup $line |tail -n +3 |sed -n "s/Address:/$line :/p" >> $url/recon/httprobe/assetsToBeChecked.txt; done 
	echo "[+} Outputting itmes in scope..."
fi


	mapfile -t scopeArray < "$2"

	while read -r col1 col2 col3; do 
		for item in "${!scopeArray[@]}"; do 
			if [[ $col3 == "${scopeArray[item]}" ]]; then 
				echo "[+] $col1 $col2 $col3 is in scope!" |tee $url/recon/inScope.txt
			fi
		done 
	done < "$url/recon/assetsToBeChecked.txt"
	cat $url/recon/inScope.txt | awk '{print $3}' > $url/recon/toNmap.txt
else
	echo "[-] No scope supplied, skipping scope check..."
fi

if [ -f "$scopeFile" ]; then

	echo "[+] Scanning for open ports against in scope targets..."
	nmap -iL $url/recon/toNmap.txt -T4 -sC -sV -oA $url/recon/scans/scanned.txt

else 
	echo "[-] No scope supplied, skipping active Nmap scan..."
fi

echo "[+] Checking for possible subdomain takeover..."

if [ ! -f "$url/recon/potential_takeovers/potential_takeovers.txt" ];then
	touch $url/recon/potential_takeovers/potential_takeovers.txt
fi

subjack -w $url/recon/final.txt -t 100 -timeout 30 -ssl -c ~/go-workspace/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $url/recon/potential_takeovers/potential_takeovers.txt


echo "[+] Scraping wayback data..."
cat $url/recon/final.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
for line in $(cat $url/recon/wayback/params/wayback_params.txt);do echo $line'=';done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output... This can take up a lot of space." && du -h $url/recon/wayback/extensions/
for line in $(cat $url/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]];then
		echo $line >> $url/recon/wayback/extensions/js1.txt
		sort -u $url/recon/wayback/extensions/js1.txt >> $url/recon/wayback/extensions/js.txt
	fi
done 
	echo "[+] Removing js1.txt" 
	rm $url/recon/wayback/extensions/js1.txt
	du -h $url/recon/wayback/extensions/ 
	echo " "

for line in $(cat $url/recon/wayback/wayback_output.txt);do 
	ext="${line##*.}"
	if [[ "$ext" == "html" ]];then
		echo $line >> $url/recon/wayback/extensions/jsp1.txt
		sort -u $url/recon/wayback/extensions/jsp1.txt >> $url/recon/wayback/extensions/jsp.txt
	fi
done
	echo "[+] Removing jsp1.txt"
	rm $url/recon/wayback/extensions/jsp1.txt
	du -h $url/recon/wayback/extensions/ 
	echo " " 

for line in $(cat $url/recon/wayback/wayback_output.txt);do 
	ext="${line##*.}"
	if [[ "$ext" == "json" ]];then
		echo $line >> $url/recon/wayback/extensions/json1.txt
		sort -u $url/recon/wayback/extensions/json1.txt >> $url/recon/wayback/extensions/json.txt
	fi
done
	echo "[+] Removing json1.txt"
	rm $url/recon/wayback/extensions/json1.txt
	du -h $url/recon/wayback/extensions/ 
	echo " "

for line in $(cat $url/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "php" ]];then
		echo $line >> $url/recon/wayback/extensions/php1.txt
		sort -u $url/recon/wayback/extensions/php1.txt >> $url/recon/wayback/extensions/php.txt
	fi
done
	echo "[+] Removing php1.txt"
	rm $url/recon/wayback/extensions/php1.txt
	du -h $url/recon/wayback/extensions/ 
	echo " " 

for line in $(cat $url/recon/wayback/wayback_output.txt);do 
	ext="${line##*.}"
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $url/recon/wayback/extensions/aspx1.txt
		sort -u $url/recon/wayback/extensions/aspx1.txt >> $url/recon/wayback/extensions/aspx.txt
	fi
done
	echo "[+] Removing aspx1.txt " 
       	rm $url/recon/wayback/extensions/aspx1.txt
	du -h $url/recon/wayback/extensions/ 
	echo " " 

echo "[+] Running GoWitness against all compiled domains, HTTP then HTTPS..."

gowitness file --source=$url/recon/httprobe/alive.txt -d $url/recon/gowitness/ --prefix-http

gowitness file --source=$url/recon/httprobe/alive.txt -d $url/recon/gowitness/ --prefix-https

echo "[+] Script Finished..."

date
