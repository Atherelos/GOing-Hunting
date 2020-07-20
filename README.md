GOing-Hunting
A dirty little bash wrapper around some external recon tools with some scope checking in place. 

Planning to expand it further based on suggestions. 

Usage: `./GOing-hunting.sh domain/url path/to/scopefile.txt`

Dockerised version coming soon! 

Getting GOing-Hunting running (Kali)

First, install the package
 `sudo apt install -y golang`
Then add the following to your .bashrc
```
 export GOROOT=/usr/lib/go
 export GOPATH=$HOME/go
 export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

Reload your .bashrc or shell config file. 
` source .bashrc`
Install AssetFinder
 `go get -u github.com/tomnomnom/assetfinder`
Install HTTProbe
 `go get -u github.com/tomnomnom/httprobe`
Install WayBackURLs
 `go get github.com/tomnomnom/waybackurls`
Install Subjack
 `go get github.com/haccer/subjack`
Nmap should be installed, if not, what are you doing here?
Install gowitness
 `go get -u github.com/sensepost/gowitness`

Thanks to Tomnomnom / Haccer / Sensepost for the heavy lifting.
