#!/bin/bash	
#Disclaimer, this is a work in progress! 
#Addtionally, with a large target the wayback data can get pretty large. Tested against a company operating a bug bounty program and it got up to about 16gb. 

echo "[+] Script Started"
date

url=$1
scopeFile=$2 
folder=${url/.*/}
ips=$folder/recon/ips.txt

echo "[+] Checking GO tools are installed..."

assetFinder=$(which assetfinder)
httProbe=$(which httprobe)
subJack=$(which subjack)
waybackUrls=$(which waybackurls)
goWitness=$(which gowitness)

if 
	[ -z "$assetFinder" ]; then
		echo "[-] assetfinder is not installed"
fi
if 
	[ -z "$httProbe" ]; then
		echo "[-] httprobe is not installed"
fi
if 
	[ -z "$subJack" ]; then
		echo "[-] subjack is not installed"
fi
if 
	[ -z "$waybackUrls" ]; then
		echo "[-] waybackurls is not installed"
fi
if 
	[ -z "$goWitness" ]; then
		echo "[-] gowitness is not installed"
fi


if [ ! -d "$folder" ];then
	mkdir $folder
fi
if [ ! -d "$folder/recon" ];then
	mkdir $folder/recon
fi
if [ ! -d "$folder/recon/scans" ];then
	mkdir $folder/recon/scans
fi
if [ ! -d "$folder/recon/httprobe" ];then
	mkdir $folder/recon/httprobe
fi
if [ ! -d "$folder/recon/potential_takeovers" ];then
	mkdir $folder/recon/potential_takeovers
fi
if [ ! -d "$folder/recon/gowitness" ];then
	mkdir $folder/recon/gowitness
fi
if [ ! -d "$folder/recon/wayback" ];then
	mkdir $folder/recon/wayback
fi
if [ ! -d "$folder/recon/wayback/params" ];then
	mkdir $folder/recon/wayback/params
fi
if [ ! -d "$folder/recon/wayback/extensions" ];then
	mkdir $folder/recon/wayback/extensions
fi
if [ ! -f "$folder/recon/httprobe/alive.txt" ];then
	touch $folder/recon/httprobe/alive.txt
fi
if [ ! -f "$folder/recon/final.txt" ];then
	touch $folder/recon/final.txt
fi

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $url >> $folder/recon/assets.txt
cat $folder/recon/assets.txt | grep $1 >> $folder/recon/final.txt
rm $folder/recon/assets.txt

echo "[+] Probing for alive domains on 80..."
cat $folder/recon/final.txt | sort -u | httprobe -s -p http:80 | sed 's/http\?:\/\///' | tr -d ':80' >> $folder/recon/httprobe/a.txt
sort -u $folder/recon/httprobe/a.txt > $folder/recon/httprobe/alive.txt
rm $folder/recon/httprobe/a.txt

echo "[+] Probing for alive domains on 443..."
cat $folder/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $folder/recon/httprobe/a.txt
sort -u $folder/recon/httprobe/a.txt >> $folder/recon/httprobe/alive.txt
rm $folder/recon/httprobe/a.txt

echo "[+] Probing for alive domains on 8443..."
cat $folder/recon/final.txt | sort -u | httprobe -s -p https:8443 | sed 's/https\?:\/\///' | tr -d ':8443' >> $folder/recon/httprobe/a.txt
sort -u $folder/recon/httprobe/a.txt >> $folder/recon/httprobe/alive.txt
rm $folder/recon/httprobe/a.txt

echo "[+] Probing for alive domains on 8080..."
cat $folder/recon/final.txt | sort -u | httprobe -s -p http:8080 | sed 's/http\?:\/\///' | tr -d ':8080' >> $folder/recon/httprobe/a.txt
sort -u $folder/recon/httprobe/a.txt >> $folder/recon/httprobe/alive.txt
rm $folder/recon/httprobe/a.txt

if [ -f "$scopeFile" ];then
	echo "[+] Expanding any CIDR ranges..."
	cat $scopeFile |grep -e \/ > $folder/recon/cidrIPs.txt
	cat $scopeFile |grep -v \/ > $folder/recon/ips.txt
	nmap -iL $folder/recon/cidrIPs.txt -sL -n | awk '/Nmap scan report/{print $NF}' >> $folder/recon/ips.txt
	rm $folder/recon/cidrIPs.txt
fi 


if [ -f "$scopeFile" ];then 
	echo "[+] Creating comparison file..."
	for line in $(cat $folder/recon/httprobe/alive.txt );do nslookup $line |tail -n +3 |sed -n "s/Address:/$line :/p" >> $folder/recon/httprobe/assetsToCheck.txt; done 
	echo "[+} Outputting itmes in scope..."
fi

if [ -f "$scopeFile" ]; then

	mapfile -t scopeArray < "$ips"

	while read -r col1 col2 col3; do 
		for item in "${!scopeArray[@]}"; do 
			if [[ $col3 == "${scopeArray[item]}" ]]; then 
				echo "[+] $col1 $col2 $col3 is in scope!" >> $folder/recon/httprobe/inScopeTargets.txt
				echo "$col1" >> $folder/recon/httprobe/inScopeHostnames.txt
			fi
		done 
	done < "$folder/recon/httprobe/assetsToCheck.txt"
fi 

if [ -f "$scopeFile" ]; then

	echo "[+] Nmap scan of items provided in scope file..."
	nmap -iL $2 -T4 -sC -sV -oA $folder/recon/scans/$folder

else 
	echo "[-] No scope supplied, skipping active Nmap scan..."
fi

echo "[+] Checking for possible subdomain takeover..."

if [ ! -f "$folder/recon/potential_takeovers/potential_takeovers.txt" ];then
	touch $folder/recon/potential_takeovers/potential_takeovers.txt
fi

subjack -w $folder/recon/httprobe/inScopeHostnames.txt -t 100 -timeout 30 -ssl -c ~/go-workspace/src/github.com/haccer/subjack/fingerprints.json -v 3 -o $folder/recon/potential_takeovers/potential_takeovers.txt


echo "[+] Scraping wayback data..."
cat $folder/recon/inScopeHostnames.txt | waybackurls >> $folder/recon/wayback/wayback_output.txt
sort -u $folder/recon/wayback/wayback_output.txt

echo "[+] Pulling and compiling all possible params found in wayback data..."
cat $folder/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $folder/recon/wayback/params/wayback_params.txt
for line in $(cat $folder/recon/wayback/params/wayback_params.txt);do echo $line'=';done

echo "[+] Pulling and compiling js/php/aspx/jsp/json files from wayback output... This can take up a lot of space." && du -h $folder/recon/wayback/extensions/
for line in $(cat $folder/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "js" ]];then
		echo $line >> $folder/recon/wayback/extensions/js1.txt
		sort -u $folder/recon/wayback/extensions/js1.txt >> $folder/recon/wayback/extensions/js.txt
	fi
done 
	echo "[+] Removing js1.txt" 
	rm $folder/recon/wayback/extensions/js1.txt
	du -h $folder/recon/wayback/extensions/ 
	echo " "

for line in $(cat $folder/recon/wayback/wayback_output.txt);do 
	ext="${line##*.}"
	if [[ "$ext" == "html" ]];then
		echo $line >> $folder/recon/wayback/extensions/jsp1.txt
		sort -u $folder/recon/wayback/extensions/jsp1.txt >> $folder/recon/wayback/extensions/jsp.txt
	fi
done
	echo "[+] Removing jsp1.txt"
	rm $folder/recon/wayback/extensions/jsp1.txt
	du -h $folder/recon/wayback/extensions/ 
	echo " " 

for line in $(cat $folder/recon/wayback/wayback_output.txt);do 
	ext="${line##*.}"
	if [[ "$ext" == "json" ]];then
		echo $line >> $folder/recon/wayback/extensions/json1.txt
		sort -u $folder/recon/wayback/extensions/json1.txt >> $folder/recon/wayback/extensions/json.txt
	fi
done
	echo "[+] Removing json1.txt"
	rm $folder/recon/wayback/extensions/json1.txt
	du -h $folder/recon/wayback/extensions/ 
	echo " "

for line in $(cat $folder/recon/wayback/wayback_output.txt);do
	ext="${line##*.}"
	if [[ "$ext" == "php" ]];then
		echo $line >> $folder/recon/wayback/extensions/php1.txt
		sort -u $folder/recon/wayback/extensions/php1.txt >> $folder/recon/wayback/extensions/php.txt
	fi
done
	echo "[+] Removing php1.txt"
	rm $folder/recon/wayback/extensions/php1.txt
	du -h $folder/recon/wayback/extensions/ 
	echo " " 

for line in $(cat $folder/recon/wayback/wayback_output.txt);do 
	ext="${line##*.}"
	if [[ "$ext" == "aspx" ]];then
		echo $line >> $folder/recon/wayback/extensions/aspx1.txt
		sort -u $folder/recon/wayback/extensions/aspx1.txt >> $folder/recon/wayback/extensions/aspx.txt
	fi
done
	echo "[+] Removing aspx1.txt " 
       	rm $folder/recon/wayback/extensions/aspx1.txt
	du -h $folder/recon/wayback/extensions/ 
	echo " " 

echo "[+] Running GoWitness against all compiled domains, HTTP then HTTPS..."

gowitness file --source=$folder/recon/httprobe/inScopeHostnames.txt -d $folder/recon/gowitness/ --prefix-http

gowitness file --source=$folder/recon/httprobe/inScopeHostnames.txt -d $folder/recon/gowitness/ --prefix-https

rm $folder/recon/final.txt
rm $folder/recon/ips.txt

echo "[+] Script Finished..."

date
