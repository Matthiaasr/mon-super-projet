Assessment 2 Splunk searches and screenshots
All 21 saved assessment searches, exported directly from Splunk on 15 October 2026. Each copyable SPL block is immediately followed by its matching screenshot. Only whitespace outside quoted strings has been reformatted.
How to use
Open Splunk Search & Reporting, select All time, copy a complete `spl` block and run it. Use Statistics for the tabular results. Some earlier queries specify `earliest=0` without `latest`; All time avoids an unintended upper-bound restriction. Keep the same user timezone to reproduce the displayed AEST (+1000) incident times. Dates in 2026 above a result table are search-dispatch dates, not the incident dates.
Images below link to the existing local screenshot files. Keep those files available at their current location. Original screenshot numbering is retained.
1. Data sources and coverage
Inventories the sources, counts and observed time coverage. The screenshot shows the first results page; Data_Source_Coverage.csv contains all 102 rows.
Open saved report
```spl
index=botsv3 earliest=0 latest=now
| stats count AS events min(\_time) AS first\_epoch max(\_time) AS last\_epoch dc(host) AS logging\_hosts by sourcetype
| eval first\_seen=strftime(first\_epoch,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_epoch,"%Y-%m-%d %H:%M:%S %z")
| sort - events
| table sourcetype events logging\_hosts first\_seen last\_seen
```
![Data sources and coverage results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/10-data-source-coverage-first-page.png)
2. Initial breach public bucket ACL
Shows the public READ/WRITE grants and the later removal of those grants.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="aws:cloudtrail" eventName=PutBucketAcl \*frothlywebcode\*
| spath path=requestParameters.AccessControlPolicy.AccessControlList.Grant{} output=grant
| mvexpand grant
| spath input=grant path=Grantee.URI output=group
| spath input=grant path=Permission output=permission
| where isnotnull(group)
| sort 0 \_time
| table \_time userIdentity.userName sourceIPAddress group permission
```
![Initial breach public bucket ACL results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/17-initial-breach-public-bucket-acl.png)
3. Initial breach archive tampering timeline
Shows anonymous archive replacement and subsequent web-instance downloads. The original capture crops the far-right embedded-time column; one archive GET also has a conflicting embedded date.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="aws:s3:accesslogs" \*frothlywebcode\* ("REST.PUT.OBJECT" OR "REST.GET.OBJECT" OR "REST.PUT.ACL")
| rex field=\_raw "^\\S+ (?<bucket>\\S+) \\\[(?<embedded\_time>\[^]]+)\\] (?<remote\_ip>\\S+) (?<requester>\\S+) \\S+ (?<operation>\\S+) (?<object\_key>\\S+) .\[^\\"]\*. (?<status>\\d+) \\S+ (?<bytes\_sent>\\S+) (?<object\_size>\\S+)"
| sort 0 \_time
| table \_time remote\_ip requester operation object\_key status object\_size embedded\_time
```
![Initial breach archive tampering timeline results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/18-initial-breach-archive-tampering.png)
4. Initial breach deployment download
Confirms the deployment archive download in startup output. These are grouped startup timestamps, not exact command times.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="cloud-init-output"
| rex max\_match=0 field=\_raw "(?im)(?<deployment\_line>\[^\\r\\n]\*frothlywebcode\[^\\r\\n]\*)"
| where isnotnull(deployment\_line)
| sort 0 \_time
| table \_time host deployment\_line
```
![Initial breach deployment download results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/19-initial-breach-deployment-download.png)
5. DHCP host attribution
Links the DHCP payload host name, address and MAC. Keep collector identity separate from client identity.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="stream:dhcp" host\_name="BSTOLL-L"
| stats count AS requests min(\_time) AS first\_seen max(\_time) AS last\_seen values(chaddr) AS mac by host host\_name src\_ip
| eval first\_seen=strftime(first\_seen,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_seen,"%Y-%m-%d %H:%M:%S %z")
```
![DHCP host attribution results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/02-dhcp-host-attribution.png)
6. Browser delivery sequence
Lists HTML and JavaScript request metadata, including the homepage visit and later thread 22 visit. Filenames alone do not establish malicious script contents.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="stream:http" host="BSTOLL-L" src\_ip="192.168.247.131" dest\_ip="54.67.127.227" (http\_content\_type="text/html\*" OR http\_content\_type="text/javascript")
| eval event\_time=strftime(\_time,"%Y-%m-%d %H:%M:%S.%3N %z"),full\_url=if(isnotnull(uri\_query),url."?".uri\_query,url)
| sort 0 \_time
| table event\_time full\_url http\_method status http\_referrer
```
![Browser delivery sequence results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/13-browser-delivery-sequence.png)
7. Chrome connections to Coinhive
Connects Chrome and the user context to Coinhive destinations. Communication alone does not prove accepted shares or payment.
Open saved report
```spl
index=botsv3 earliest=0 sourcetype="syslog" \*coinhive\*
| rex "sa=.(?<client\_ip>\[0-9.]+)"
| rex "da=.(?<server\_ip>\[0-9.]+)"
| rex "pn=.(?<process>\[a-zA-Z0-9.]+)"
| rex "(?<mining\_domain>\[a-zA-Z0-9.-]\*coinhive\[.]\[a-zA-Z]+)"
| table \_time client\_ip server\_ip process liuid mining\_domain
```
![Chrome connections to Coinhive results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/08-chrome-coinhive-connections.png)
8. BSTOLL Chrome CPU evidence
Shows the two Chrome instance series for PID 3400, including 149 chrome#4 samples averaging 96.70 percent CPU. Captured again on 15 October 2026 for this guide.
Open saved report
```spl
index=botsv3 earliest=0 sourcetype="PerfmonMk:Process" host="BSTOLL-L" process\_id=3400 process\_name="chrome\*"
| stats count AS samples avg(process\_cpu\_used\_percent) AS average\_cpu max(process\_cpu\_used\_percent) AS peak\_cpu min(\_time) AS first\_seen max(\_time) AS last\_seen by host process\_name process\_id
| eval average\_cpu=round(average\_cpu,2)
| convert ctime(first\_seen) ctime(last\_seen)
```
![BSTOLL Chrome CPU evidence results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/21-bstoll-chrome-cpu-evidence.png)
9. BTUN blocked mining attempts
Summarises 46 blocked Symantec alert records. These are not 46 independently proven successful attacks.
Open saved report
```spl
index=botsv3 earliest=0 sourcetype="symantec:ep:security:file"
| rex "Major,(?<endpoint>\[^,]+),"
| rex "\\\[SID: (?<signature\_id>\\d+)\\] (?<detection>\[^.]+)"
| rex "Local: (?<local\_ip>\[0-9.]+)"
| rex "Remote: ,Remote: (?<remote\_ip>\[0-9.]+)"
| stats count AS alerts min(\_time) AS first\_seen max(\_time) AS last\_seen values(local\_ip) AS local\_ip values(remote\_ip) AS remote\_ip by endpoint signature\_id detection
| convert ctime(first\_seen) ctime(last\_seen)
```
![BTUN blocked mining attempts results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/09-blocked-mining-attempts.png)
10. Correlated incident timeline
Compares website visits, mining indicators, high CPU and blocked detections. Observation boundaries are not proven attack start/end times.
Open saved report
```spl
index=botsv3 earliest=0 latest=now ((sourcetype="stream:http" host="BSTOLL-L" src\_ip="192.168.247.131" dest\_ip="54.67.127.227") OR (sourcetype="stream:dns" host="BSTOLL-L" src\_ip="192.168.247.131" \*coinhive\*) OR (sourcetype="syslog" \*coinhive\*) OR (sourcetype="PerfmonMk:Process" host="BSTOLL-L" process\_id=3400 process\_name="chrome\*" process\_cpu\_used\_percent>=90) OR sourcetype="symantec:ep:security:file")
| eval endpoint=if(sourcetype="symantec:ep:security:file","BTUN-L","BSTOLL-L"),activity=case(sourcetype="stream:http","Brewertalk HTTP visits; delivery suspected",sourcetype="stream:dns","Coinhive DNS queries",sourcetype="syslog","Chrome network connections to Coinhive",sourcetype="PerfmonMk:Process","Chrome PID 3400 CPU at least 90 percent",true(),"JSCoinminer downloads blocked")
| stats count AS records min(\_time) AS first\_epoch max(\_time) AS last\_epoch by endpoint activity sourcetype
| sort 0 first\_epoch
| eval first\_seen=strftime(first\_epoch,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_epoch,"%Y-%m-%d %H:%M:%S %z")
| table endpoint activity sourcetype records first\_seen last\_seen
```
![Correlated incident timeline results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/03-correlated-timeline.png)
11. Web server recovery lifecycle
Shows launches, target registration, termination requests and deregistration. API calls alone do not prove clean contents or final shutdown time.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="aws:cloudtrail" (eventName=TerminateInstances OR eventName=RunInstances OR eventName=DeregisterTargets OR eventName=RegisterTargets) (\*i-0cc93bade2b3cba63\* OR \*i-06fea586f3d3c8ce8\* OR \*i-09cbc261e84259b54\*)
| spath path=responseElements.instancesSet.items{}.instanceId output=response\_instance
| spath path=requestParameters.instancesSet.items{}.instanceId output=request\_instance
| spath path=requestParameters.targets{}.id output=target
| eval actor=coalesce('userIdentity.userName','userIdentity.invokedBy'),instances=coalesce(response\_instance,request\_instance,target)
| sort 0 \_time
| table \_time eventName actor instances errorCode
```
![Web server recovery lifecycle results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/20-web-server-recovery-lifecycle.png)
12. Web server compromise evidence coverage
Summarises access/error log coverage and tested keyword matches. Zero code matches are not proof of a clean server.
Open saved report
```spl
index=botsv3 earliest=0 latest=now (sourcetype="access\_combined" OR sourcetype="apache\_error")
| stats count AS records count(eval(match(\_raw,"(?i)coinhive|cryptonight|mining\[.]submit|CoinHive\[.]Anonymous"))) AS mining\_code\_matches count(eval(match(\_raw,"(?i)brewertalk|showthread\[.]php|attachment\[.]php|forumdisplay\[.]php"))) AS forum\_reference\_matches values(source) AS log\_files min(\_time) AS first\_epoch max(\_time) AS last\_epoch by host sourcetype
| eval first\_seen=strftime(first\_epoch,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_epoch,"%Y-%m-%d %H:%M:%S %z")
| table host sourcetype records mining\_code\_matches forum\_reference\_matches log\_files first\_seen last\_seen
```
![Web server compromise evidence coverage results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/14-web-server-evidence-coverage.png)
13. Web server POST request review
Parses actual request methods before counting POST/PUT requests. A failed probe or ordinary registration request is not proof of successful exploitation.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="access\_combined" (host="gacrux.i-0920036c8ca91e501" OR host="gacrux.i-0cc93bade2b3cba63")
| rex field=\_raw "^\[^ ]+ \[^ ]+ \[^ ]+ \\\[\[^]]+\\] .(?<request\_method>\[A-Z]+) (?<request\_uri>\[^ ]+) HTTP"
| where request\_method IN ("POST","PUT")
| stats count AS requests min(\_time) AS first\_epoch max(\_time) AS last\_epoch by host request\_method request\_uri
| eval first\_seen=strftime(first\_epoch,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_epoch,"%Y-%m-%d %H:%M:%S %z")
| sort 0 first\_epoch
| table host request\_method request\_uri requests first\_seen last\_seen
```
![Web server POST request review results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/15-web-server-post-review.png)
14. Security alert timestamp discrepancy
Compares indexed/displayed dates with embedded alert dates and preserves the conflict.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="symantec:ep:security:file"
| rex "^(?<recorded\_time>\[^,]+),\[^,]+,(?<endpoint>\[^,]+),"
| rex "Begin: (?<embedded\_begin>\[^,]+),End: (?<embedded\_end>\[^,]+),Occurrences: (?<occurrences>\[0-9]+)"
| rex "SID: (?<signature>\[0-9]+)"
| eval displayed\_time=strftime(\_time,"%Y-%m-%d %H:%M:%S %z")
| sort 0 \_time
| table displayed\_time recorded\_time endpoint embedded\_begin embedded\_end occurrences signature
| head 8
```
![Security alert timestamp discrepancy results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/01-security-timestamp-discrepancy.png)
15. Network sensor consistency check
Compares client traffic across collectors. Similar traffic is not automatically a duplicate or another compromised endpoint.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="stream:tcp" src\_ip="192.168.247.131" dest\_ip IN ("217.182.164.14","37.187.165.41","37.187.166.108","37.187.167.21","37.187.167.47","104.20.208.59")
| eval event\_time=strftime(\_time,"%Y-%m-%d %H:%M:%S %z")
| table event\_time host timestamp endtime flow\_id dest\_ip src\_port dest\_port bytes\_in bytes\_out
| sort 0 event\_time
```
![Network sensor consistency check results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/07-network-sensor-consistency.png)
16. Process identity discrepancy
Shows PID reuse and Chrome instance renumbering. Correlate by executable, host and time.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="PerfmonMk:Process" host="BSTOLL-L" process\_id=3400
| stats count AS samples min(\_time) AS first\_epoch max(\_time) AS last\_epoch avg(process\_cpu\_used\_percent) AS average\_cpu by host process\_id process\_name
| eval average\_cpu=round(average\_cpu,2),first\_seen=strftime(first\_epoch,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_epoch,"%Y-%m-%d %H:%M:%S %z")
| sort 0 first\_epoch
| table host process\_id process\_name samples average\_cpu first\_seen last\_seen
```
![Process identity discrepancy results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/06-process-identity-discrepancy.png)
17. CPU false positive review
Screens sustained/high CPU candidates. TiWorker and MsMpEng require path/signature/context checks before a benign verdict.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="PerfmonMk:Process"
| eval cpu=tonumber(process\_cpu\_used\_percent),high\_cpu=if(cpu>=90,1,0)
| stats count(cpu) AS samples sum(high\_cpu) AS high\_cpu\_samples avg(cpu) AS average\_cpu max(Elapsed\_Time) AS elapsed\_seconds min(\_time) AS first\_epoch max(\_time) AS last\_epoch by host process\_name process\_id
| where samples>=10 AND elapsed\_seconds>=300 AND high\_cpu\_samples>=5
| eval average\_cpu=round(average\_cpu,2),high\_cpu\_percent=round(100\*high\_cpu\_samples/samples,1),first\_seen=strftime(first\_epoch,"%Y-%m-%d %H:%M:%S %z"),last\_seen=strftime(last\_epoch,"%Y-%m-%d %H:%M:%S %z")
| sort - high\_cpu\_percent
| table host process\_name process\_id samples high\_cpu\_samples average\_cpu high\_cpu\_percent first\_seen last\_seen
```
![CPU false positive review results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/05-cpu-false-positive-review.png)
18. Endpoint coverage and detection gaps
Checks Symantec records for endpoint mentions. Missing BSTOLL-L mentions indicate a visibility gap, not a measured false-negative rate.
Open saved report
```spl
index=botsv3 earliest=0 latest=now sourcetype="symantec:\*"
| stats count AS total\_records count(eval(searchmatch("\*BSTOLL-L\*"))) AS BSTOLL\_mentions count(eval(searchmatch("\*BTUN-L\*"))) AS BTUN\_mentions by sourcetype
| sort sourcetype
```
![Endpoint coverage and detection gaps results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/04-endpoint-coverage-gap.png)
19. Mining payload and payout evidence check
Tests script, protocol and payout indicators within the combined mining-indicator set. Keyword searches have bounded visibility.
Open saved report
```spl
index=botsv3 earliest=0 latest=now (\*coinhive\* OR \*CoinHive.Anonymous\* OR \*coinhive.min.js\* OR \*cryptonight\* OR \*mining.subscribe\* OR \*mining.submit\* OR \*hash\_accepted\* OR \*accepted\_hashes\* OR \*mining.authorize\* OR \*stratum\*)
| stats count AS matching\_records count(eval(searchmatch("\*CoinHive.Anonymous\* OR \*coinhive.min.js\*"))) AS script\_code\_matches count(eval(searchmatch("\*mining.subscribe\* OR \*mining.submit\* OR \*hash\_accepted\* OR \*accepted\_hashes\* OR \*mining.authorize\* OR \*stratum\*"))) AS mining\_protocol\_matches count(eval(searchmatch("\*payout\* OR \*wallet\* OR \*payment\* OR \*site\_key\* OR \*sitekey\*"))) AS payout\_or\_account\_keyword\_matches values(sourcetype) AS sources
```
![Mining payload and payout evidence check results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/11-mining-payload-and-payout-check.png)
20. Mining protocol false positive check
Reviews the three protocol keyword hits, which are NTP stratum references rather than mining protocol evidence.
Open saved report
```spl
index=botsv3 earliest=0 latest=now (\*mining.subscribe\* OR \*mining.submit\* OR \*hash\_accepted\* OR \*accepted\_hashes\* OR \*mining.authorize\* OR \*stratum\*)
| eval event\_time=strftime(\_time,"%Y-%m-%d %H:%M:%S %z")
| table event\_time host sourcetype \_raw
```
![Mining protocol false positive check results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/12-ntp-protocol-false-positive.png)
21. Independent wallet and payout keyword review
Independently searches wallet and payout terms. WalletService and domain-name matches do not establish a cryptocurrency address or payment.
Open saved report
```spl
index=botsv3 earliest=0 latest=now (\*payout\* OR \*wallet\* OR \*monero\* OR \*xmrig\* OR \*minerd\*)
| rex field=\_raw "(?i)(?<wallet\_context>.{0,60}wallet.{0,140})"
| stats count AS records count(eval(searchmatch("\*payout\*"))) AS payout\_hits count(eval(searchmatch("\*monero\* OR \*xmrig\* OR \*minerd\*"))) AS other\_mining\_hits first(wallet\_context) AS example by sourcetype
```
![Independent wallet and payout keyword review results](/Users/jackboulding/Library/CloudStorage/OneDrive-CanberraInstituteofTechnology/Documents/2026/Semester 2/Gather, analyse and interpret threat data/Assesments/Assesment 2/Investigation Evidence/Screenshots/16-independent-wallet-payout-review.png)
