# MiniTwit

Java version of Flask's MiniTwit example built with the Spark web microframework, Freemarker, Spring and HSQLDB (as an in-memory database).

## Prerequisites

- Java 8

- Maven

## How to run it

1. Clone the repository and go to the root directory.

2. Execute `mvn compile exec:java`

3. Open in your browser `http://localhost:4567/`

4. Log in as user001 with password user001, or user002/user002, or user003/user003 until user010/user010, or sign up yourself. If your e-mail address has an associated Gravatar image, this will be used as your profile image.

# MiniTwit Docker 
## Setup


1. Open Docker hub : https://hub.docker.com/repository/docker/mhnamadi/minitwit16java

2. Docker pull : 

  
        docker pull mhnamadi/minitwit16java 
        

        docker run -it --rm --name my-maven-project -v "$(pwd)":/usr/src/mymaven -p 4567:4567 -w /usr/src/mymaven maven:3.3-jdk-8 mvn compile exec:java
        
4. Log in as user001 with password user001, or user002/user002, or user003/user003 until user010/user010, or sign up yourself. If your e-mail address has an associated Gravatar image, this will be used as your profile image.
        
## Introduction XSS

When looking at XSS (Cross-Site Scripting), there are three generally recognized forms of XSS:

1 . Reflected or Stored
2 . DOM Based XSS.

Cross-site scripting (or XSS) is a code vulnerability that occurs when an attacker “injects” a malicious script into an otherwise trusted website. The injected script gets downloaded and executed by the end user’s browser when the user interacts with the compromised website. Since the script came from a trusted website, it cannot be distinguished from a legitimate script.

## Owasp

https://owasp.org/www-community/attacks/xss/

## SAST Tools : 

Find With SAST Tools : SonarQube Developer Plans


![Getting Started](40.png)


Find With SAST Tools : Snyk Enterprise Plans

![Getting Started](43.png)


## Fix Guide :  

Detailed paths and remediation

Introduced through: com.sparkjava:minitwit@1.0-SNAPSHOT › com.sparkjava:spark-core@2.5.4 › org.eclipse.jetty:jetty-server@9.3.6.v20151106


## Contributing : 
 
We encourage you to contribute to Project

## Twitter Contributor :

   https:// 
   
## Report Example

Top XSS reports from HackerOne:

1. [Bypass for #488147 enables stored XSS on https://paypal.com/signin again](https://hackerone.com/reports/510152) to PayPal - 2520 upvotes, $20000
2. [Stored XSS on https://paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) to PayPal - 639 upvotes, $18900
3. [Reflected XSS on https://www.glassdoor.com/employers/sem-dual-lp/](https://hackerone.com/reports/846338) to Glassdoor - 630 upvotes, $1000
4. [Stored XSS in Wiki pages](https://hackerone.com/reports/526325) to GitLab - 594 upvotes, $4500
5. [Stored XSS on imgur profile](https://hackerone.com/reports/484434) to Imgur - 589 upvotes, $650
6. [Reflected XSS in OAUTH2 login flow ](https://hackerone.com/reports/697099) to LINE - 466 upvotes, $1989
7. [XSS in steam react chat client](https://hackerone.com/reports/409850) to Valve - 448 upvotes, $7500
8. [Cross-Site-Scripting on www.tiktok.com and m.tiktok.com leading to Data Exfiltration](https://hackerone.com/reports/968082) to TikTok - 448 upvotes, $3860
9. [XSS vulnerable parameter in a location hash](https://hackerone.com/reports/146336) to Slack - 438 upvotes, $1100
10. [Panorama UI XSS leads to Remote Code Execution via Kick/Disconnect Message](https://hackerone.com/reports/631956) to Valve - 406 upvotes, $9000
11. [Blind XSS on image upload](https://hackerone.com/reports/1010466) to CS Money - 397 upvotes, $1000
12. [Stored XSS Vulnerability](https://hackerone.com/reports/643908) to WordPress - 389 upvotes, $500
13. [Reflected XSS and sensitive data exposure, including payment details, on lioncityrentals.com.sg](https://hackerone.com/reports/340431) to Uber - 366 upvotes, $4000
14. [Stored XSS in wordpress.com](https://hackerone.com/reports/733248) to Automattic - 346 upvotes, $650
15. [HEY.com email stored XSS](https://hackerone.com/reports/982291) to Basecamp - 344 upvotes, $5000
16. [Reflected XSS on www.hackerone.com and resources.hackerone.com](https://hackerone.com/reports/840759) to HackerOne - 344 upvotes, $500
17. [Reflected XSS in TikTok endpoints](https://hackerone.com/reports/1350887) to TikTok - 332 upvotes, $4500
18. [Stored XSS in Private Message component (BuddyPress)](https://hackerone.com/reports/487081) to WordPress - 331 upvotes, $500
19. [Blind XSS on Twitter's internal Big Data panel at █████████████](https://hackerone.com/reports/1207040) to Twitter - 330 upvotes, $5040
20. [XSS while logging using Google](https://hackerone.com/reports/691611) to Shopify - 323 upvotes, $1750
21. [Stored XSS in my staff name fired in another your internal panel](https://hackerone.com/reports/946053) to Shopify - 315 upvotes, $5000
22. [DOM XSS on duckduckgo.com search](https://hackerone.com/reports/868934) to DuckDuckGo - 314 upvotes, $0
23. [Reflected XSS](https://hackerone.com/reports/739601) to Bumble - 313 upvotes, $1000
24. [Reflected XSS at https://pay.gold.razer.com escalated to account takeover](https://hackerone.com/reports/723060) to Razer - 287 upvotes, $750
25. [Cross-site Scripting (XSS) - Stored in RDoc wiki pages](https://hackerone.com/reports/662287) to GitLab - 274 upvotes, $3500
26. [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/808862) to Visma Public - 268 upvotes, $250
27. [Persistent XSS on keybase.io via "payload" field in `/user/sigchain_signature.toffee` template](https://hackerone.com/reports/245296) to Keybase - 265 upvotes, $3000
28. [Stored XSS in markdown via the DesignReferenceFilter ](https://hackerone.com/reports/1212067) to GitLab - 263 upvotes, $16000
29. [Account takeover through the combination of cookie manipulation and XSS](https://hackerone.com/reports/534450) to Grammarly - 251 upvotes, $2000
30. [Arbitrary File Upload to Stored XSS](https://hackerone.com/reports/808821) to Visma Public - 245 upvotes, $250
31. [Stored xss in address field in billing activity at https://shop.aaf.com/Order/step1/index.cfm](https://hackerone.com/reports/411690) to Alliance of American Football  - 235 upvotes, $1500
32. [XSS via Direct Message deeplinks](https://hackerone.com/reports/341908) to Twitter - 225 upvotes, $2940
33. [XSS and Open Redirect on MoPub Login](https://hackerone.com/reports/683298) to Twitter - 225 upvotes, $1540
34. [Unsafe charts embedding implementation leads to cross-account stored XSS and SSRF](https://hackerone.com/reports/708589) to New Relic - 222 upvotes, $2500
35. [Cross-site Scripting (XSS) on HackerOne careers page](https://hackerone.com/reports/474656) to HackerOne - 222 upvotes, $500
36. [Reflected XSS on www.hackerone.com via Wistia embed code](https://hackerone.com/reports/986386) to HackerOne - 221 upvotes, $500
37. [[panel.city-mobil.ru/admin/] Blind XSS into username](https://hackerone.com/reports/746505) to Mail.ru - 219 upvotes, $750
38. [[www.zomato.com] Blind XSS on one of the Admin Dashboard](https://hackerone.com/reports/724889) to Zomato - 211 upvotes, $750
39. [Stored XSS in developer.uber.com](https://hackerone.com/reports/131450) to Uber - 208 upvotes, $7500
40. [XSS At "pages.et.uber.com"](https://hackerone.com/reports/156098) to Uber - 205 upvotes, $0
41. [Stored XSS on reports.](https://hackerone.com/reports/485748) to Twitter - 197 upvotes, $700
42. [Ability to create own account UUID leads to stored XSS](https://hackerone.com/reports/249131) to Upserve  - 195 upvotes, $1500
43. [Config override using non-validated query parameter allows at least reflected XSS by injecting configuration into state](https://hackerone.com/reports/1082847) to Grammarly - 192 upvotes, $3000
44. [XSS and cache poisoning via upload.twitter.com on ton.twitter.com](https://hackerone.com/reports/84601) to Twitter - 191 upvotes, $2520
45. [DOM Based XSS in www.hackerone.com via PostMessage](https://hackerone.com/reports/398054) to HackerOne - 188 upvotes, $500
46. [H1514 DOMXSS on Embedded SDK via Shopify.API.setWindowLocation abusing cookie Stuffing](https://hackerone.com/reports/422043) to Shopify - 186 upvotes, $5000
47. [Chaining Bugs: Leakage of CSRF token which leads to Stored XSS and Account Takeover (xs1.tribalwars.cash)](https://hackerone.com/reports/604120) to InnoGames - 186 upvotes, $1100
48. [Stored Xss Vulnerability on ████████](https://hackerone.com/reports/380103) to U.S. Dept Of Defense - 185 upvotes, $0
49. [XSS STORED AT socialclub.rockstargames.com (add friend request from profile attacker)](https://hackerone.com/reports/220852) to Rockstar Games - 183 upvotes, $750
50. [XSS on Desktop Client](https://hackerone.com/reports/473950) to Keybase - 173 upvotes, $1000
51. [Stored XSS & SSRF in Lark Docs](https://hackerone.com/reports/892049) to Lark Technologies - 168 upvotes, $3000
52. [Reflected Cross site Scripting (XSS) on www.starbucks.com](https://hackerone.com/reports/438240) to Starbucks - 163 upvotes, $375
53. [XSS  at https://exchangemarketplace.com/blogsearch](https://hackerone.com/reports/1145162) to Shopify - 162 upvotes, $3500
54. [DOM Based XSS via postMessage at https://inventory.upserve.com/login/](https://hackerone.com/reports/603764) to Upserve  - 161 upvotes, $2500
55. [Cross-account stored XSS at embedded charts](https://hackerone.com/reports/709883) to New Relic - 154 upvotes, $3625
56. [xss on https://www.rockstargames.com/GTAOnline/jp/screens/ ](https://hackerone.com/reports/507494) to Rockstar Games - 153 upvotes, $750
57. [XSS in gist integration](https://hackerone.com/reports/11073) to Slack - 152 upvotes, $500
58. [IE only: stored Cross-Site Scripting (XSS) vulnerability through Program Asset identifier](https://hackerone.com/reports/449351) to HackerOne - 148 upvotes, $2500
59. [Stored XSS in notes (charts) because of insecure chart data JSON generation](https://hackerone.com/reports/507132) to New Relic - 144 upvotes, $4250
60. [Stealing contact form data on www.hackerone.com using Marketo Forms XSS with postMessage frame-jumping and jQuery-JSONP](https://hackerone.com/reports/207042) to HackerOne - 140 upvotes, $1500
61. [CSRF leads to a stored self xss](https://hackerone.com/reports/323005) to Imgur - 140 upvotes, $500
62. [Stored XSS in IE11 on hackerone.com via custom fields ](https://hackerone.com/reports/1173040) to HackerOne - 139 upvotes, $2500
63. [Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)](https://hackerone.com/reports/998398) to Elastic - 139 upvotes, $2000
64. [XSS via message subject - mobile application](https://hackerone.com/reports/368912) to Mail.ru - 138 upvotes, $1000
65. [XSS - main page - search[user_id] parameter](https://hackerone.com/reports/477771) to OLX - 136 upvotes, $0
66. [Persistent XSS in Note objects](https://hackerone.com/reports/508184) to GitLab - 134 upvotes, $4500
67. [XSS reflected on [https://www.pixiv.net]](https://hackerone.com/reports/766633) to pixiv - 134 upvotes, $500
68. [Reflected XSS in twitterflightschool.com](https://hackerone.com/reports/770349) to Twitter - 132 upvotes, $1120
69. [Stored XSS on byddypress Plug-in via groups name](https://hackerone.com/reports/592316) to WordPress - 131 upvotes, $450
70. [Reflected XSS at https://www.paypal.com/ppcreditapply/da/us](https://hackerone.com/reports/753835) to PayPal - 130 upvotes, $1900
71. [Stored XSS in 'Notes'](https://hackerone.com/reports/788732) to Visma Public - 130 upvotes, $250
72. [Stored XSS when uploading files to an invoice](https://hackerone.com/reports/808672) to Visma Public - 128 upvotes, $250
73. [Content spoofing and potential Cross-Site Scripting vulnerability on www.hackerone.com](https://hackerone.com/reports/374919) to HackerOne - 123 upvotes, $5000
74. [Reflected/Stored XSS on duckduckgo.com](https://hackerone.com/reports/1110229) to DuckDuckGo - 123 upvotes, $0
75. [Stored XSS in localhost:* via integrated torrent downloader](https://hackerone.com/reports/681617) to Brave Software - 121 upvotes, $0
76. [Stored XSS in custom emoji](https://hackerone.com/reports/1198517) to GitLab - 120 upvotes, $3000
77. [Stored XSS in private message](https://hackerone.com/reports/729424) to Shopify - 120 upvotes, $1000
78. [XSS via referrer parameter](https://hackerone.com/reports/867616) to Twitter - 118 upvotes, $0
79. [web.icq.com XSS in chat message via contact info](https://hackerone.com/reports/810872) to Mail.ru - 116 upvotes, $1000
80. ["😂" + Unauthenticated Stored XSS in API at https://api.my.games/comments/v1/comments/update/](https://hackerone.com/reports/853637) to Mail.ru - 116 upvotes, $0
81. [A reflected XSS in python/Lib/DocXMLRPCServer.py](https://hackerone.com/reports/705420) to Internet Bug Bounty - 115 upvotes, $500
82. [Stored XSS in Document Title](https://hackerone.com/reports/1321407) to Localize - 115 upvotes, $50
83. [[First 30] Stored XSS on login.uber.com/oauth/v2/authorize via redirect_uri parameter](https://hackerone.com/reports/392106) to Uber - 114 upvotes, $3000
84. [Stored XSS vulnerability in comments on *.wordpress.com](https://hackerone.com/reports/707720) to Automattic - 114 upvotes, $350
85. [Reflected XSS on https://inventory.upserve.com/ (affects IE users only)](https://hackerone.com/reports/469841) to Upserve  - 113 upvotes, $1200
86. [Stored XSS in backup scanning plan name](https://hackerone.com/reports/961046) to Acronis - 113 upvotes, $500
87. [Stored XSS in Snapmatic + R★Editor comments](https://hackerone.com/reports/309531) to Rockstar Games - 111 upvotes, $1000
88. [Reflected XSS on https://www.uber.com ](https://hackerone.com/reports/390386) to Uber - 110 upvotes, $2000
89. [XSS on any Shopify shop via abuse of the HTML5 structured clone algorithm in postMessage listener on "/:id/digital_wallets/dialog"](https://hackerone.com/reports/231053) to Shopify - 107 upvotes, $3000
90. [XSS via JavaScript evaluation of an attacker controlled resource at www.pornhub.com](https://hackerone.com/reports/944518) to Pornhub - 106 upvotes, $250
91. [XSS: Group search terms](https://hackerone.com/reports/396370) to Vanilla - 105 upvotes, $300
92. [Stored XSS on any page in most Uber domains](https://hackerone.com/reports/217739) to Uber - 103 upvotes, $6000
93. [Persistent XSS (unvalidated Open Graph embed) at LinkedIn.com](https://hackerone.com/reports/425007) to LinkedIn - 103 upvotes, $0
94. [DOM XSS at https://www.thx.com in IE/Edge browser](https://hackerone.com/reports/702981) to Razer - 102 upvotes, $250
95. [XSS at https://www.glassdoor.com/Salary/* via filter.jobTitleExact](https://hackerone.com/reports/789689) to Glassdoor - 101 upvotes, $900
96. [DOM Based XSS in www.hackerone.com via PostMessage (bypass of #398054)](https://hackerone.com/reports/499030) to HackerOne - 101 upvotes, $565
97. [Stored XSS in Shopify Chat ](https://hackerone.com/reports/756729) to Shopify - 101 upvotes, $500
98. [Stored XSS on team.slack.com using new Markdown editor of posts inside the Editing mode and using javascript-URIs](https://hackerone.com/reports/132104) to Slack - 100 upvotes, $1000
99. [Insecure file upload in xiaoai.mi.com Lead to Stored  XSS](https://hackerone.com/reports/882733) to Xiaomi - 98 upvotes, $50
100. [Reflected XSS in *.myshopify.com/account/register](https://hackerone.com/reports/470206) to Shopify - 96 upvotes, $1500
101. [[www.zomato.com] Blind XSS in one of the admin dashboard](https://hackerone.com/reports/461272) to Zomato - 96 upvotes, $500
102. [Reflected XSS on https://make.wordpress.org via 'channel' parameter](https://hackerone.com/reports/659419) to WordPress - 95 upvotes, $387
103. [RXSS to Stored XSS - forums.pubg.com | URL parameter](https://hackerone.com/reports/756697) to PUBG - 95 upvotes, $0
104. [XSS [flow] - on www.paypal.com/paypalme/my/landing (requires user interaction)](https://hackerone.com/reports/425200) to PayPal - 94 upvotes, $2900
105. [XSS in request approvals](https://hackerone.com/reports/402658) to GitLab - 93 upvotes, $3000
106. [Reflected XSS in pubg.com](https://hackerone.com/reports/751870) to PUBG - 93 upvotes, $0
107. [Stored XSS on app.crowdsignal.com + your-subdomain.survey.fm via Embed Media](https://hackerone.com/reports/920005) to Automattic - 92 upvotes, $100
108. [DOM-based XSS on mobile.line.me](https://hackerone.com/reports/736272) to LINE - 91 upvotes, $1989
109. [Reflected XSS in VPN Appliance](https://hackerone.com/reports/1386438) to New Relic - 91 upvotes, $1024
110. [DOM XSS at www.forescout.com in Microsoft Edge and IE Browser](https://hackerone.com/reports/704266) to ForeScout Technologies - 91 upvotes, $1000
111. [CSTI at Plugin page leading to active stored XSS (Publisher name)](https://hackerone.com/reports/587829) to New Relic - 90 upvotes, $2500
112. [Stored XSS](https://hackerone.com/reports/408978) to Mail.ru - 89 upvotes, $500
113. [Stored XSS via `Create a Fetish` section.](https://hackerone.com/reports/1085914) to FetLife - 89 upvotes, $500
114. [Stored XSS in vanilla](https://hackerone.com/reports/481360) to Vanilla - 89 upvotes, $300
115. [DOM-Based XSS in tumblr.com](https://hackerone.com/reports/882546) to Automattic - 88 upvotes, $350
116. [Stored XSS in vanilla](https://hackerone.com/reports/496405) to Vanilla - 88 upvotes, $300
117. [XSS in Email Input [intensedebate.com]](https://hackerone.com/reports/1037714) to Automattic - 88 upvotes, $100
118. [capsula.mail.ru - Admin blind stored XSS](https://hackerone.com/reports/874387) to Mail.ru - 86 upvotes, $1500
119. [Stored XSS in "Create Groups"](https://hackerone.com/reports/647130) to GitLab - 84 upvotes, $2500
120. [xss](https://hackerone.com/reports/306554) to Pornhub - 84 upvotes, $100
121. [Blind XSS in operator's interface for 33slona.ru](https://hackerone.com/reports/659760) to Mail.ru - 83 upvotes, $600
122. [Reflected XSS in https://light.mail.ru/login via page](https://hackerone.com/reports/502016) to Mail.ru - 83 upvotes, $500
123. [DOM based XSS on *.██████.com via document.domain sink in Safari](https://hackerone.com/reports/398163) to ██████ - 83 upvotes, $0
124. [Unrestricted file upload leads to Stored XSS](https://hackerone.com/reports/880099) to GitLab - 82 upvotes, $1500
125. [Persistent DOM-based XSS in https://help.twitter.com via localStorage](https://hackerone.com/reports/297968) to Twitter - 82 upvotes, $1120
126. [Flash Based Reflected XSS on www.grouplogic.com/jwplayer/player.swf](https://hackerone.com/reports/859806) to Acronis - 82 upvotes, $0
127. [[pay.gold.razer.com] Stored XSS - Order payment](https://hackerone.com/reports/706916) to Razer - 81 upvotes, $1500
128. [DOMXSS in redirect param](https://hackerone.com/reports/361287) to Semmle - 81 upvotes, $750
129. [XSS on $shop$.myshopify.com/admin/ and partners.shopify.com via whitelist bypass in SVG icon for sales channel applications](https://hackerone.com/reports/232174) to Shopify - 80 upvotes, $5000
130. [Stored XSS via malicious key value of Synthetics monitor tag when visiting an Insights dashboard with filtering enabled](https://hackerone.com/reports/1067321) to New Relic - 80 upvotes, $2123
131. [Potential unprivileged Stored XSS through wp_targeted_link_rel](https://hackerone.com/reports/509930) to WordPress - 80 upvotes, $650
132. [Html Injection and Possible XSS in sms-be-vip.twitter.com](https://hackerone.com/reports/150179) to Twitter - 80 upvotes, $420
133. [Urgent! Stored XSS at plugin's violations leading to account takeover](https://hackerone.com/reports/602527) to New Relic - 79 upvotes, $2500
134. [Reflected XSS в /video](https://hackerone.com/reports/1052856) to VK.com - 79 upvotes, $500
135. [Reflect XSS on Mobile Search page ](https://hackerone.com/reports/380246) to Redtube - 79 upvotes, $250
136. [Reflected XSS on transact.playstation.com using postMessage from the opening window](https://hackerone.com/reports/900619) to PlayStation - 78 upvotes, $1000
137. [Stored XSS in Email Templates via link](https://hackerone.com/reports/1376672) to Judge.me  - 77 upvotes, $500
138. [Reflected XSS on http://www.grouplogic.com/files/glidownload/verify.asp](https://hackerone.com/reports/859395) to Acronis - 77 upvotes, $200
139. [stored XSS in hey.com message content](https://hackerone.com/reports/988272) to Basecamp - 76 upvotes, $750
140. [Stored XSS in email](https://hackerone.com/reports/387272) to Mail.ru - 75 upvotes, $1000
141. [Defacement of catalog.data.gov via web cache poisoning to stored DOMXSS](https://hackerone.com/reports/303730) to GSA Bounty - 75 upvotes, $750
142. [██████ DOM XSS via Shopify.API.remoteRedirect](https://hackerone.com/reports/646505) to Shopify - 75 upvotes, $500
143. [Stored XSS via Angular Expression injection via Subject while starting conversation with other users.](https://hackerone.com/reports/1095934) to FetLife - 75 upvotes, $500
144. [[https://city-mobil.ru/taxiserv] Blind XSS into username](https://hackerone.com/reports/746497) to Mail.ru - 74 upvotes, $750
145. [Stored XSS on https://app.crowdsignal.com/surveys/[Survey-Id]/question - Bypass](https://hackerone.com/reports/974271) to Automattic - 74 upvotes, $150
146. [DOM XSS on duckduckgo.com search](https://hackerone.com/reports/876148) to DuckDuckGo - 74 upvotes, $0
147. [XSS from arbitrary attachment upload.](https://hackerone.com/reports/831703) to Qulture.Rocks - 74 upvotes, $0
148. [Stored XSS in Discounts section](https://hackerone.com/reports/618031) to Shopify - 73 upvotes, $1000
149. [xss stored](https://hackerone.com/reports/798599) to Shopify - 73 upvotes, $1000
150. [XSS via POST request to https://account.mail.ru/signup/](https://hackerone.com/reports/759090) to Mail.ru - 73 upvotes, $1000
151. [Reflected XSS in https://www.intensedebate.com/js/getCommentLink.php](https://hackerone.com/reports/1043804) to Automattic - 73 upvotes, $250
152. [Reflected XSS online-store-git.shopifycloud.com](https://hackerone.com/reports/1410459) to Shopify - 72 upvotes, $3500
153. [Stored XSS in main page of a project caused by arbitrary script payload in group "Default initial branch name"](https://hackerone.com/reports/1256777) to GitLab - 72 upvotes, $3000
154. [Passive stored XSS at broadcast room](https://hackerone.com/reports/423797) to Chaturbate - 72 upvotes, $1000
155. [Blind Stored XSS in HackerOne's Sal 4.1.4.2149 (sal.████.com)](https://hackerone.com/reports/995995) to HackerOne - 72 upvotes, $0
156. [Reflective Cross-site Scripting via Newsletter Form](https://hackerone.com/reports/709336) to Shopify - 71 upvotes, $2000
157. [Stored XSS that allow an attacker to read victim mailboxes contacts in mail.ru and my.com application](https://hackerone.com/reports/900543) to Mail.ru - 71 upvotes, $1000
158. [Reflected XSS in https://www.starbucks.co.jp/store/search/](https://hackerone.com/reports/496375) to Starbucks - 71 upvotes, $250
159. [XSS on https://partners.acronis.com/](https://hackerone.com/reports/979204) to Acronis - 71 upvotes, $50
160. [XSS via Cookie in Mail.ru](https://hackerone.com/reports/690072) to Mail.ru - 70 upvotes, $1000
161. [[account.mail.ru] XSS-уязвимость в форме авторизации](https://hackerone.com/reports/889874) to Mail.ru - 70 upvotes, $1000
162. [Multiple XSS on account settings that can hijack any users in the company. ](https://hackerone.com/reports/503298) to Twitter - 70 upvotes, $700
163. [Reflected cross-site scripting on multiple Starbucks assets.](https://hackerone.com/reports/629745) to Starbucks - 70 upvotes, $150
164. [Reflected XSS in \<any\>.myshopify.com through theme preview](https://hackerone.com/reports/226428) to Shopify - 69 upvotes, $2000
165. [XSS on tiktok.com](https://hackerone.com/reports/1322104) to TikTok - 69 upvotes, $2000
166. [Possibility to overwrite any file in the vpe.cdn.vimeo.tv leads to the Stored XSS for the all customers on the embed.vhx.tv](https://hackerone.com/reports/452559) to VHX - 69 upvotes, $1500
167. [Blind XSS in redtube administering site my.reflected.net](https://hackerone.com/reports/603941) to Redtube - 69 upvotes, $1000
168. [help.shopify.com Cross Site Scripting](https://hackerone.com/reports/564196) to Shopify - 69 upvotes, $500
169. [stripo.email reflected xss](https://hackerone.com/reports/714521) to Stripo Inc - 69 upvotes, $0
170. [Blind Stored XSS Against Lahitapiola Employees - Session and Information leakage](https://hackerone.com/reports/135154) to LocalTapiola - 68 upvotes, $5000
171. [WordPress Flash XSS in *flashmediaelement.swf*](https://hackerone.com/reports/134546) to Automattic - 68 upvotes, $1337
172. [Potential stored Cross-Site Scripting vulnerability in Support Backend](https://hackerone.com/reports/858894) to HackerOne - 68 upvotes, $0
173. [Stored XSS в личных сообщениях](https://hackerone.com/reports/181823) to VK.com - 67 upvotes, $1500
174. [Reflected XSS & Open Redirect at mcs main domain](https://hackerone.com/reports/996262) to Mail.ru - 67 upvotes, $1000
175. [Reflected XSS on secure.chaturbate.com](https://hackerone.com/reports/413412) to Chaturbate - 67 upvotes, $800
176. [Stored Self XSS on https://app.crowdsignal.com (in Photo Insert App) + Stored XSS on https://*your-subdomain*.survey.fm](https://hackerone.com/reports/667188) to Automattic - 67 upvotes, $150
177. [XSS on Videos IA](https://hackerone.com/reports/910427) to DuckDuckGo - 67 upvotes, $0
178. [Blind Stored XSS Against Lahitapiola Employees - Session and Information leakage](https://hackerone.com/reports/159498) to LocalTapiola - 66 upvotes, $3000
179. [xss is triggered on your web](https://hackerone.com/reports/1121900) to Shopify - 66 upvotes, $2900
180. [[dev.twitter.com] XSS and Open Redirect](https://hackerone.com/reports/260744) to Twitter - 66 upvotes, $1120
181. [POST-based XSS on apps.shopify.com](https://hackerone.com/reports/429679) to Shopify - 66 upvotes, $500
182. [Multiple DOMXSS on Amplify Web Player](https://hackerone.com/reports/88719) to Twitter - 65 upvotes, $2520
183. [Cross-site Scripting (XSS) - DOM on https://account.mail.ru/user/garage?back_url=https://mail.ru](https://hackerone.com/reports/996303) to Mail.ru - 65 upvotes, $1000
184. [Stored XSS through Facebook Page Connection](https://hackerone.com/reports/267570) to Shopify - 65 upvotes, $500
185. [DOM XSS triggered in secure support desk](https://hackerone.com/reports/512065) to QIWI - 65 upvotes, $500
186. [xss in https://www.uber.com](https://hackerone.com/reports/145278) to Uber - 64 upvotes, $7000
187. [URL Advisor component in KIS products family is vulnerable to Universal XSS](https://hackerone.com/reports/463915) to Kaspersky - 64 upvotes, $2500
188. [Possible DOM XSS on app.hey.com](https://hackerone.com/reports/1010132) to Basecamp - 64 upvotes, $1000
189. [reflected xss in e.mail.ru](https://hackerone.com/reports/1379297) to Mail.ru - 64 upvotes, $1000
190. [web.icq.com XSS in chat message via contact info](https://hackerone.com/reports/634648) to Mail.ru - 64 upvotes, $500
191. [RCE, SQLi, IDOR, Auth Bypass and XSS at [staff.███.edu.eg ]](https://hackerone.com/reports/404874) to ██████ - 64 upvotes, $0
192. [Cross Site Scripting using Email parameter in Ads endpoint 1](https://hackerone.com/reports/953041) to TikTok - 63 upvotes, $896
193. [Wormable stored XSS in www.evernote.com](https://hackerone.com/reports/397968) to Evernote - 62 upvotes, $0
194. [Reflected XSS on www.grouplogic.com/video.asp](https://hackerone.com/reports/859802) to Acronis - 62 upvotes, $0
195. [Stored XSS in Acronis Cyber Protect Console](https://hackerone.com/reports/1064095) to Acronis - 61 upvotes, $500
196. [Stored XSS in Post title (PoC)](https://hackerone.com/reports/942859) to Imgur - 61 upvotes, $250
197. [Stored XSS in [https://streamlabs.com/dashboard#/*goal] pages](https://hackerone.com/reports/1049012) to Logitech - 61 upvotes, $100
198. [Reflected XSS and Server Side Template Injection  in all HubSpot CMSes](https://hackerone.com/reports/399462) to HubSpot - 61 upvotes, $0
199. [Blind XSS in Mobpub Marketplace Admin Production | Sentry via demand.mopub.com (User-Agent)](https://hackerone.com/reports/275518) to Twitter - 60 upvotes, $840
200. [[www.zomato.com] Blind XSS in one of the Admin Dashboard](https://hackerone.com/reports/419731) to Zomato - 60 upvotes, $500
201. [[http_server] Stored XSS in the filename when directories listing](https://hackerone.com/reports/578138) to Node.js third-party modules - 60 upvotes, $0
202. [Cross-site Scripting (XSS) - Stored on ads.tiktok.com in Text  field](https://hackerone.com/reports/1376961) to TikTok - 59 upvotes, $999
203. [Stored XSS | api.mapbox.com | IE 11 | Styles name](https://hackerone.com/reports/763812) to Mapbox - 59 upvotes, $600
204. [Cross-Site Scripting (XSS) on www.starbucks.com | .co.uk login pages](https://hackerone.com/reports/881115) to Starbucks - 59 upvotes, $500
205. [DOM based CSS Injection on grammarly.com](https://hackerone.com/reports/500436) to Grammarly - 59 upvotes, $250
206. [Reflected XSS on $Any$.myshopify.com/admin](https://hackerone.com/reports/422707) to Shopify - 58 upvotes, $1500
207. [Stored XSS on https://events.hackerone.com](https://hackerone.com/reports/1028332) to HackerOne - 58 upvotes, $0
208. [Reflected xss on ads.tiktok.com using `from` parameter.](https://hackerone.com/reports/1452375) to TikTok - 57 upvotes, $6000
209. [Unrestricted file upload when creating quotes allows for Stored XSS](https://hackerone.com/reports/788397) to Visma Public - 57 upvotes, $250
210. [[web.icq.com] Stored XSS in Account Name](https://hackerone.com/reports/1069045) to Mail.ru - 56 upvotes, $1000
211. [Singapore - Unrestricted File Upload Leads to XSS on campaign.starbucks.com.sg/api/upload](https://hackerone.com/reports/883151) to Starbucks - 56 upvotes, $0
212. [Stored XSS on activity](https://hackerone.com/reports/391390) to Shopify - 55 upvotes, $2000
213. [The Custom Emoji Page has a Reflected XSS](https://hackerone.com/reports/258198) to Slack - 55 upvotes, $1250
214. [Reflected XSS at http://promotion.molthailand.com/index.php via promotion_id parameter](https://hackerone.com/reports/772116) to Razer - 55 upvotes, $250
215. [XSS account.mail.ru](https://hackerone.com/reports/1038906) to Mail.ru - 54 upvotes, $1000
216. [Reflected XSS on https://www.glassdoor.com/job-listing/spotlight](https://hackerone.com/reports/1265390) to Glassdoor - 54 upvotes, $500
217. [DOM-Based XSS in tumblr.com](https://hackerone.com/reports/949382) to Automattic - 54 upvotes, $350
218. [WAF bypass via double encoded non standard ASCII chars permitted a reflected XSS on response page not found pages - (629745 bypass)](https://hackerone.com/reports/716761) to Starbucks - 54 upvotes, $150
219. [Persistent Cross-Site Scripting in default Laravel installation](https://hackerone.com/reports/392797) to Laravel - 54 upvotes, $0
220. [Stored XSS on upload files leads to steal cookie](https://hackerone.com/reports/765679) to Palo Alto Software - 54 upvotes, $0
221. [[manage.jumpbikes.com] Blind XSS on Jump admin panel via user name](https://hackerone.com/reports/472470) to Uber - 53 upvotes, $4000
222. [Unrestricted File Upload Results in Cross-Site Scripting Attacks](https://hackerone.com/reports/1005355) to Uber - 53 upvotes, $2000
223. [Stored-XSS on wiki pages](https://hackerone.com/reports/1087061) to GitLab - 53 upvotes, $1500
224. [HTML Injection with XSS possible ](https://hackerone.com/reports/381553) to Imgur - 53 upvotes, $750
225. [Self XSS](https://hackerone.com/reports/982510) to Shopify - 52 upvotes, $500
226. [Cross site scripting via file upload in subdomain ads.tiktok.com](https://hackerone.com/reports/1433125) to TikTok - 51 upvotes, $500
227. [Stored XSS in Intense Debate comment system](https://hackerone.com/reports/1039750) to Automattic - 51 upvotes, $200
228. [DOMXSS in Tweetdeck](https://hackerone.com/reports/119471) to Twitter - 50 upvotes, $1120
229. [Possibility to inject a malicious JavaScript code in any file on tags.tiqcdn.com results in a stored XSS on any page in most Uber domains](https://hackerone.com/reports/256152) to Uber - 49 upvotes, $6000
230. [Stored XSS on the job page](https://hackerone.com/reports/856554) to GitLab - 49 upvotes, $3000
231. [Reflect XSS and CSP Bypass on https://www.paypal.com/businesswallet/currencyConverter/ ](https://hackerone.com/reports/799881) to PayPal - 49 upvotes, $2900
232. [Stored XSS on support.rockstargames.com](https://hackerone.com/reports/265384) to Rockstar Games - 49 upvotes, $1000
233. [XSS through `__e2e_action_id` delivered by JSONP](https://hackerone.com/reports/259100) to Quora - 49 upvotes, $600
234. [Reflected XSS in m.imgur.com](https://hackerone.com/reports/149855) to Imgur - 49 upvotes, $500
235. [OX (Guard): Stored Cross-Site Scripting via Incoming Email](https://hackerone.com/reports/156258) to Open-Xchange - 48 upvotes, $1000
236. [XSS within Shopify Email App - Admin](https://hackerone.com/reports/869831) to Shopify - 48 upvotes, $500
237. [XSS Reflected in m.vk.com](https://hackerone.com/reports/1011463) to VK.com - 48 upvotes, $500
238. [[careers.informatica.com] Reflected Cross Site Scripting to XSS Shell Possible](https://hackerone.com/reports/147196) to Informatica - 48 upvotes, $0
239. [Stored XSS in collabora via user name](https://hackerone.com/reports/968232) to Nextcloud - 48 upvotes, $0
240. [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1106238) to GitLab - 47 upvotes, $3000
241. [(Prerelease UI) Stored XSS via role name in JSON chart](https://hackerone.com/reports/520630) to New Relic - 47 upvotes, $2500
242. [[my.games, lootdog.io] XSS via MCS Bucket](https://hackerone.com/reports/974473) to Mail.ru - 47 upvotes, $1333
243. [csp bypass + xss](https://hackerone.com/reports/153666) to Twitter - 47 upvotes, $1120
244. [Cross Site Scripting(XSS) on IRCCloud Badges Page (using Parameter Pollution)](https://hackerone.com/reports/150083) to IRCCloud - 47 upvotes, $500
245. [Stored XSS in wordpress.com](https://hackerone.com/reports/1054526) to Automattic - 47 upvotes, $350
246. [Stored XSS on store.my.games](https://hackerone.com/reports/1073925) to Mail.ru - 47 upvotes, $200
247. [[Android] XSS via start ContentActivity](https://hackerone.com/reports/189793) to Quora - 47 upvotes, $150
248. [Stored XSS in markdown when redacting references](https://hackerone.com/reports/836649) to GitLab - 46 upvotes, $5000
249. [XSS on Issue reference numbers](https://hackerone.com/reports/831962) to GitLab - 46 upvotes, $1500
250. [Stored xss](https://hackerone.com/reports/415484) to Shopify - 46 upvotes, $1000
251. [XSS в сюжетах.](https://hackerone.com/reports/1115763) to VK.com - 46 upvotes, $500
252. [Reflected XSS ](https://hackerone.com/reports/569241) to Shopify - 46 upvotes, $0
253. [Stored XSS on auth.uber.com/oauth/v2/authorize via redirect_uri parameter leads to Account Takeover](https://hackerone.com/reports/397497) to Uber - 45 upvotes, $3000
254. [ Cross-site scripting (reflected)](https://hackerone.com/reports/176754) to Twitter - 45 upvotes, $2520
255. [Blind XSS via Suspended Ticket Recovery](https://hackerone.com/reports/450389) to Zendesk - 45 upvotes, $1000
256. [xss stored in https://your store.myshopify.com/admin/](https://hackerone.com/reports/887879) to Shopify - 45 upvotes, $1000
257. [Blind stored xss [parcel.grab.com] \> name parameter ](https://hackerone.com/reports/251224) to Grab - 45 upvotes, $750
258. [DOM based XSS on /GTAOnline/tw/starterpack/](https://hackerone.com/reports/508517) to Rockstar Games - 45 upvotes, $750
259. [H1514 DOM XSS on checkout.shopify.com via postMessage handler on /:id/sandbox/google_maps](https://hackerone.com/reports/423218) to Shopify - 45 upvotes, $500
260. [Reflected xss and open redirect on larksuite.com using /?back_uri= parameter.](https://hackerone.com/reports/955606) to Lark Technologies - 45 upvotes, $500
261. [Reflected XSS in https://lite.pubg.com](https://hackerone.com/reports/751284) to PUBG - 45 upvotes, $0
262. [Stored XSS in photo comment functionality](https://hackerone.com/reports/172227) to Pornhub - 44 upvotes, $1500
263. [DOM XSS on https://www.rockstargames.com/GTAOnline/feedback](https://hackerone.com/reports/803934) to Rockstar Games - 44 upvotes, $1250
264. [Stored XSS when you read eamils. \<style\>](https://hackerone.com/reports/274844) to Mail.ru - 44 upvotes, $1000
265. [[auth2.zomato.com] Reflected XSS at `oauth2/fallbacks/error` | ORY Hydra an OAuth 2.0 and OpenID Connect Provider](https://hackerone.com/reports/456333) to Zomato - 44 upvotes, $250
266. [Reflected XSS in https://blocked.myndr.net](https://hackerone.com/reports/824433) to Myndr - 44 upvotes, $0
267. [Stored XSS via Mermaid Prototype Pollution vulnerability](https://hackerone.com/reports/1280002) to GitLab - 43 upvotes, $3000
268. [[dev.twitter.com] XSS and Open Redirect Protection Bypass](https://hackerone.com/reports/330008) to Twitter - 43 upvotes, $1120
269. [Store XSS](https://hackerone.com/reports/187410) to Slack - 43 upvotes, $500
270. [Reflected XSS through multiple inputs in the issue collector on Jira](https://hackerone.com/reports/380354) to Roblox - 43 upvotes, $500
271. [Reflected XSS on https://help.glassdoor.com/GD_HC_EmbeddedChatVF](https://hackerone.com/reports/1244053) to Glassdoor - 43 upvotes, $500
272. [XSS via X-Forwarded-Host header](https://hackerone.com/reports/1392935) to Omise - 43 upvotes, $200
273. [Stored XSS in profile page](https://hackerone.com/reports/1084183) to Acronis - 43 upvotes, $50
274. [Stored XSS in Mermaid when viewing Markdown files](https://hackerone.com/reports/1212822) to GitLab - 42 upvotes, $3000
275. [DOM XSS on https://biz.mail.ru/domains/goto/mail/ via parameter pollution](https://hackerone.com/reports/1039643) to Mail.ru - 42 upvotes, $1000
276. [[e.mail.ru] XSS в поиске](https://hackerone.com/reports/378582) to Mail.ru - 42 upvotes, $750
277. [[intensedebate.com] XSS Reflected POST-Based ](https://hackerone.com/reports/1040533) to Automattic - 42 upvotes, $100
278. [XSS Stored via Upload avatar PNG [HTML] File in accounts.shopify.com](https://hackerone.com/reports/964550) to Shopify - 42 upvotes, $0
279. [Stored XSS in [https://dashboard.doppler.com/workplace/*/logs] pages](https://hackerone.com/reports/1073726) to Doppler - 42 upvotes, $0
280. [Cross-site Scripting (XSS) - Stored](https://hackerone.com/reports/1318395) to Mail.ru - 42 upvotes, $0
281. [Stored XSS in profile activity feed messages](https://hackerone.com/reports/231444) to Rockstar Games - 41 upvotes, $1000
282. [XSS on services.shopify.com](https://hackerone.com/reports/591786) to Shopify - 41 upvotes, $500
283. [Blind XSS Stored On Admin Panel Through Name Parameter In [ https://technoatom.mail.ru/]](https://hackerone.com/reports/766434) to Mail.ru - 41 upvotes, $250
284. [Stored xss ](https://hackerone.com/reports/149154) to Algolia - 41 upvotes, $100
285. [(HackerOne SSO-SAML) Login CSRF, Open Redirect, and Self-XSS Possible Exploitation](https://hackerone.com/reports/171398) to HackerOne - 41 upvotes, $0
286. [Reflected xss on 8x8.com subdomain](https://hackerone.com/reports/770513) to 8x8 - 41 upvotes, $0
287. [IE 11 Self-XSS on Jira Integration Preview Base Link](https://hackerone.com/reports/212721) to HackerOne - 40 upvotes, $750
288. [XSS в личных сообщениях](https://hackerone.com/reports/293105) to ok.ru - 40 upvotes, $500
289. [Очень жесткая XSS в личных сообщениях m.ok.ru](https://hackerone.com/reports/302253) to ok.ru - 40 upvotes, $500
290. [Stored xss on message reply](https://hackerone.com/reports/546220) to Mail.ru - 40 upvotes, $500
291. [WooCommerce: Persistent XSS via customer address (state/county)](https://hackerone.com/reports/530499) to Automattic - 40 upvotes, $350
292. [Stored XSS in Jetpack's Simple Payment Module by Contributors / Authors](https://hackerone.com/reports/402753) to Automattic - 40 upvotes, $350
293. [Stored XSS (client-side, using cookie poisoning) on the pornhubpremium.com](https://hackerone.com/reports/311948) to Pornhub - 40 upvotes, $250
294. [Stored XSS in Brower `name` field reflected in two pages](https://hackerone.com/reports/348076) to New Relic - 39 upvotes, $3000
295. [Stored XSS in blog comments through Shopify API](https://hackerone.com/reports/192210) to Shopify - 39 upvotes, $1000
296. [Stored XSS in '' Section and WAF Bypass](https://hackerone.com/reports/382625) to Semrush - 39 upvotes, $600
297. [XSS in HTML Content Generated by Flash Slideshow Maker (All Versions)](https://hackerone.com/reports/404898) to Socusoft - 39 upvotes, $0
298. [Cross Site Scripting via CVE-2018-5230 on https://apps.topcoder.com](https://hackerone.com/reports/781284) to Topcoder - 39 upvotes, $0
299. [Reflected XSS in lert.uber.com](https://hackerone.com/reports/191810) to Uber - 38 upvotes, $3000
300. [Reflected XSS on multiple uberinternal.com domains](https://hackerone.com/reports/326449) to Uber - 38 upvotes, $2000
301. [XSS в upload.php](https://hackerone.com/reports/142135) to VK.com - 38 upvotes, $1500
302. [HTML injection (with XSS possible) on the https://www.data.gov/issue/ using media_url attribute](https://hackerone.com/reports/263226) to GSA Bounty - 38 upvotes, $900
303. [[IRCCloud Android] XSS in ImageViewerActivity](https://hackerone.com/reports/283063) to IRCCloud - 38 upvotes, $500
304. [Stored XSS on buy button](https://hackerone.com/reports/397088) to Shopify - 38 upvotes, $500
305. [XSS on https://app.mopub.com/reports/custom/add/ [new-d1]](https://hackerone.com/reports/692352) to Twitter - 38 upvotes, $280
306. [Reflected XSS in https://www.starbucks.com/account/create/redeem/MCP131XSR via xtl_amount, xtl_coupon_code, xtl_amount_type parameters](https://hackerone.com/reports/531042) to Starbucks - 38 upvotes, $250
307. [Reflected XSS via "Error" parameter on https://admin.acronis.com/admin/su/](https://hackerone.com/reports/970878) to Acronis - 38 upvotes, $50
308. [DOM Based XSS in mycrypto.com](https://hackerone.com/reports/324303) to MyCrypto - 38 upvotes, $0
309. [CSTI on https://www.ecobee.com leads to XSS](https://hackerone.com/reports/500518) to ecobee - 38 upvotes, $0
310. [Moodle XSS on  evolve.glovoapp.com](https://hackerone.com/reports/1165540) to Glovo - 38 upvotes, $0
311. [Reflected XSS on https://www.uber.com](https://hackerone.com/reports/708081) to Uber - 37 upvotes, $1000
312. [Mattermost Server OAuth Flow Cross-Site Scripting](https://hackerone.com/reports/1216203) to Mattermost - 37 upvotes, $900
313. [[qiwi.me] Stored XSS](https://hackerone.com/reports/736236) to QIWI - 37 upvotes, $500
314. [Blind XSS - Report review - Admin panel](https://hackerone.com/reports/314126) to Zomato - 37 upvotes, $350
315. [DOM based XSS in the WooCommerce plugin](https://hackerone.com/reports/507139) to Automattic - 37 upvotes, $275
316. [Stored XSS on the https://www.redtube.com/users/[profile]/collections](https://hackerone.com/reports/380204) to Redtube - 36 upvotes, $1500
317. [(BYPASS) Open redirect and XSS in supporthiring.shopify.com](https://hackerone.com/reports/158434) to Shopify - 36 upvotes, $1000
318. [Stored XSS on demo app link ](https://hackerone.com/reports/439912) to Shopify - 36 upvotes, $750
319. [Stored XSS on www.starbucks.com.sg/careers/career-center/career-landing-*](https://hackerone.com/reports/507957) to Starbucks - 36 upvotes, $500
320. [dom based xss on [hello.merchant.razer.com]](https://hackerone.com/reports/767944) to Razer - 36 upvotes, $500
321. [Reflected xss в m.vk.com/chatjoin](https://hackerone.com/reports/316475) to VK.com - 36 upvotes, $500
322. [ XSS through chat messages](https://hackerone.com/reports/683792) to Vanilla - 36 upvotes, $300
323. [Self XSS on Acronis Cyber Cloud](https://hackerone.com/reports/957229) to Acronis - 36 upvotes, $100
324. [Stored Cross-site Scripting on devicelock.com/forum/](https://hackerone.com/reports/1122513) to Acronis - 36 upvotes, $50
325. [Cross-Site Scripting through search form on mtnplay.co.zm](https://hackerone.com/reports/761573) to MTN Group - 36 upvotes, $0
326. [[stored xss, pornhub.com] stream post function](https://hackerone.com/reports/138075) to Pornhub - 35 upvotes, $1500
327. [Stored XSS in [shop].myshopify.com/admin/orders/[id]](https://hackerone.com/reports/214044) to Shopify - 35 upvotes, $1500
328. [Stored XSS in galleries - https://www.redtube.com/gallery/[id] path](https://hackerone.com/reports/380207) to Redtube - 35 upvotes, $1500
329. [Multiple stored XSS in WordPress](https://hackerone.com/reports/221507) to WordPress - 35 upvotes, $1200
330. [CSRF in 'set.php' via age causes stored XSS on 'get.php' - http://www.rockstargames.com/php/videoplayer_cache/get.php'](https://hackerone.com/reports/152013) to Rockstar Games - 35 upvotes, $750
331. [Persistent XSS in www.starbucks.com](https://hackerone.com/reports/188972) to Starbucks - 35 upvotes, $500
332. [XSS on product comments in transfers](https://hackerone.com/reports/738072) to Shopify - 35 upvotes, $500
333. [Persistent XSS in https://sandbox.reverb.com/item/](https://hackerone.com/reports/333008) to Reverb.com - 35 upvotes, $400
334. [Reflected XSS - gratipay.com](https://hackerone.com/reports/262852) to Gratipay - 35 upvotes, $0
335. [Reflected XSS on https://www.olx.co.id/iklan/*.html via "ad_type" parameter](https://hackerone.com/reports/630265) to OLX - 35 upvotes, $0
336. [Хранимый XSS в Business-аккаунте, на странице компании](https://hackerone.com/reports/771882) to DRIVE.NET, Inc. - 35 upvotes, $0
337. [Account takeover via XSS](https://hackerone.com/reports/735638) to Rocket.Chat - 35 upvotes, $0
338. [Store-XSS in error message of build-dependencies ](https://hackerone.com/reports/950190) to GitLab - 34 upvotes, $3000
339. [Stored XSS in blob viewer](https://hackerone.com/reports/806571) to GitLab - 34 upvotes, $2000
340. [XSS *.myshopify.com/collections/vendors?q=](https://hackerone.com/reports/324136) to Shopify - 34 upvotes, $1500
341. [Stored XSS in the guide's GameplayVersion (www.dota2.com)](https://hackerone.com/reports/380045) to Valve - 34 upvotes, $750
342. [DOM XSS via Shopify.API.Modal.initialize](https://hackerone.com/reports/602767) to Shopify - 34 upvotes, $500
343. [CSS Injection to disable app & potential message exfil](https://hackerone.com/reports/679969) to Slack - 34 upvotes, $500
344. [Timeline Editor Self-XSS (Previous Fix #738072 Incomplete)](https://hackerone.com/reports/755679) to Shopify - 34 upvotes, $500
345. [www.starbucks.co.uk Reflected XSS via utm_source parameter](https://hackerone.com/reports/140616) to Starbucks - 34 upvotes, $375
346. [XSS found on Snapchat website](https://hackerone.com/reports/125849) to Snapchat - 34 upvotes, $250
347. [[allods.mail.ru] - WebCache Poisoning Host Header lead to Potential Stored XSS](https://hackerone.com/reports/1262408) to Mail.ru - 34 upvotes, $0
348. [Blind Stored XSS Via Staff Name](https://hackerone.com/reports/948929) to Shopify - 33 upvotes, $3000
349. [Stored XSS Deleting Menu Links in the Shopify Admin](https://hackerone.com/reports/263876) to Shopify - 33 upvotes, $1000
350. [DOM Based xss on https://www.rockstargames.com/ ( 1 )](https://hackerone.com/reports/475442) to Rockstar Games - 33 upvotes, $850
351. [XSS in biz.mail.ru/error](https://hackerone.com/reports/268245) to Mail.ru - 33 upvotes, $500
352. [Stored XSS ](https://hackerone.com/reports/299806) to Open-Xchange - 33 upvotes, $500
353. [Reflected XSS at https://www.glassdoor.co.in/FAQ/Microsoft-Question-FAQ200086-E1651.htm?countryRedirect=true via PATH](https://hackerone.com/reports/1016253) to Glassdoor - 33 upvotes, $500
354. [XSS in IE11 on portswigger.net via Flash](https://hackerone.com/reports/182160) to PortSwigger Web Security - 33 upvotes, $350
355. [Bypass Filter and get Stored Xss ](https://hackerone.com/reports/299424) to Shopify - 32 upvotes, $3000
356. [CSS Injection on /embed/ via bgcolor parameter leaks user's CSRF token and allows for XSS ](https://hackerone.com/reports/386334) to Chaturbate - 32 upvotes, $999
357. [Stored XSS при удалении группы из беседы (m.vk.com)](https://hackerone.com/reports/1101500) to VK.com - 32 upvotes, $500
358. [Clipboard DOM-based XSS](https://hackerone.com/reports/1196958) to GitLab - 32 upvotes, $500
359. [XSS For Profile Name](https://hackerone.com/reports/674426) to Vanilla - 32 upvotes, $300
360. [Reflected XSS in photogallery component on [https://market.av.ru]](https://hackerone.com/reports/988271) to Azbuka Vkusa - 32 upvotes, $100
361. [Cross site scripting - XSRF Token](https://hackerone.com/reports/858255) to Nextcloud - 32 upvotes, $0
362. [Blind Stored XSS Payload fired at the backend on https://█████████/](https://hackerone.com/reports/1051369) to U.S. Dept Of Defense - 32 upvotes, $0
363. [Reflected XSS on delivery.glovoapp.com](https://hackerone.com/reports/1264805) to Glovo - 32 upvotes, $0
364. [Stored XSS on developer.uber.com via admin account compromise](https://hackerone.com/reports/152067) to Uber - 31 upvotes, $5000
365. [Reflected XSS on Partners Subdomain](https://hackerone.com/reports/390181) to Uber - 31 upvotes, $2000
366. [[Java] CWE-079: Query to detect XSS with JavaServer Faces (JSF)](https://hackerone.com/reports/1339898) to GitHub Security Lab - 31 upvotes, $1800
367. [Stored XSS at https://linkpop.com](https://hackerone.com/reports/1441988) to Shopify - 31 upvotes, $1600
368. [XSS in $shop$.myshopify.com/admin/ via twine template injection in "Shopify.API.Modal.input" method when using a malicious app](https://hackerone.com/reports/217790) to Shopify - 31 upvotes, $1000
369. [XSS on "widgets.shopifyapps.com" via "stripping" attribute and "shop" parameter](https://hackerone.com/reports/246794) to Shopify - 31 upvotes, $1000
370. [XSS in message e.mail.ru ](https://hackerone.com/reports/1011035) to Mail.ru - 31 upvotes, $1000
371. [Stored XSS in chat topic due to insecure emoticon parsing on any message type](https://hackerone.com/reports/429298) to Chaturbate - 31 upvotes, $450
372. [Cookie based XSS on http://ftp1.thx.com](https://hackerone.com/reports/748217) to Razer - 31 upvotes, $375
373. [XSS https://agent.postamat.tech/ в профиле + дисклоз секретной информации](https://hackerone.com/reports/365093) to QIWI - 31 upvotes, $200
374. [Blind Stored XSS in https://partners.acronis.com/admin which lead to sensitive information/PII leakage](https://hackerone.com/reports/1028820) to Acronis - 31 upvotes, $150
375. [Reflected XSS on partners.cloudflare.com](https://hackerone.com/reports/131397) to Cloudflare Vulnerability Disclosure - 31 upvotes, $0
376. [XSS leads to RCE on the RocketChat desktop client.](https://hackerone.com/reports/899964) to Rocket.Chat - 31 upvotes, $0
377. [Bypassing Content-Security-Policy leads to open-redirect and iframe xss](https://hackerone.com/reports/1166766) to Stripo Inc - 31 upvotes, $0
378. [Stored-XSS in merge requests](https://hackerone.com/reports/977697) to GitLab - 30 upvotes, $3500
379. [Reflected XSS POST method at partners.uber.com](https://hackerone.com/reports/129582) to Uber - 30 upvotes, $3000
380. [Xss was found by exploiting the URL markdown on http://store.steampowered.com](https://hackerone.com/reports/313250) to Valve - 30 upvotes, $1000
381. [XSS-уязвимость, связанная с загрузкой файлов](https://hackerone.com/reports/375886) to VK.com - 30 upvotes, $1000
382. [Cross-site scripting in "Contact customer" form](https://hackerone.com/reports/294505) to Shopify - 30 upvotes, $500
383. [Stored XSS in https://productreviews.shopifyapps.com/proxy/v4/reviews/product](https://hackerone.com/reports/168458) to Shopify - 30 upvotes, $500
384. [Reflected Xss On https://vk.com/search](https://hackerone.com/reports/1454359) to VK.com - 30 upvotes, $500
385. [[https://app.recordedfuture.com] - Reflected XSS via username parameter ](https://hackerone.com/reports/1201134) to Recorded Future - 30 upvotes, $300
386. [[FG-VD-19-022] Wordpress WooCommerce Cross-Site Scripting Vulnerability Notification](https://hackerone.com/reports/495583) to Automattic - 30 upvotes, $200
387. [[api.tumblr.com] Exploiting clickjacking vulnerability to trigger self DOM-based XSS](https://hackerone.com/reports/953579) to Automattic - 30 upvotes, $150
388. [Reflected XSS on av.ru via `q` parameter at https://av.ru/collections/*](https://hackerone.com/reports/965663) to Azbuka Vkusa - 30 upvotes, $150
389. [XSS risk reduction with X-XSS-Protection: 1; mode=block header](https://hackerone.com/reports/94909) to Radancy - 30 upvotes, $10
390. [XSS inside HTML Link Tag](https://hackerone.com/reports/504984) to OLX - 30 upvotes, $0
391. [DOM XSS on duckduckgo.com search](https://hackerone.com/reports/921635) to DuckDuckGo - 30 upvotes, $0
392. [Stored XSS on top.mail.ru](https://hackerone.com/reports/1241107) to Mail.ru - 30 upvotes, $0
393. [Reflected Cross-Site scripting in : mtn.bj](https://hackerone.com/reports/1264832) to MTN Group - 30 upvotes, $0
394. [Stored XSS on profile page via Steam display name](https://hackerone.com/reports/282604) to Rockstar Games - 29 upvotes, $1250
395. [stored XSS (angular injection) in support.rockstargames.com using zendesk register form via name parameter](https://hackerone.com/reports/354262) to Rockstar Games - 29 upvotes, $1000
396. [XSS in $shop$.myshopify.com/admin/ via "Button Objects" in malicious app](https://hackerone.com/reports/217745) to Shopify - 29 upvotes, $800
397. [SSRF & Blind XSS in Gravatar email ](https://hackerone.com/reports/1100096) to Automattic - 29 upvotes, $750
398. [Self-XSS in password reset functionality](https://hackerone.com/reports/286667) to Shopify - 29 upvotes, $500
399. [XSS в колбек апи в сообществах ](https://hackerone.com/reports/261966) to VK.com - 29 upvotes, $500
400. [Xss At Shopify Email App](https://hackerone.com/reports/1339356) to Shopify - 29 upvotes, $500
401. [Self-Stored XSS - Chained with login/logout CSRF](https://hackerone.com/reports/632017) to Zomato - 29 upvotes, $300
402. [DOM Based XSS in Discourse Search](https://hackerone.com/reports/191890) to Discourse - 29 upvotes, $256
403. [Stored XSS at https://app.smtp2go.com/settings/users/  ](https://hackerone.com/reports/912865) to SMTP2GO - 29 upvotes, $0
404. [Reflected XSS and possible SSRF/XXE on https://events.hackerone.com/conferences/get_recording_slides_xml.xml?url=myserver/xss.xml](https://hackerone.com/reports/1028396) to HackerOne - 29 upvotes, $0
405. [Reflected XSS and Blind out of band command injection at subdomain dstuid-ww.dst.ibm.com](https://hackerone.com/reports/410334) to IBM - 29 upvotes, $0
406. [Self xss in product reviews](https://hackerone.com/reports/1029668) to Shopify - 28 upvotes, $3500
407. [Reflected XSS on developer.uber.com via Angular template injection](https://hackerone.com/reports/125027) to Uber - 28 upvotes, $3000
408. [CRLF and XSS stored on ton.twitter.com](https://hackerone.com/reports/191380) to Twitter - 28 upvotes, $1680
409. [ Stored XSS(Cross Site Scripting) In Slack App Name](https://hackerone.com/reports/159460) to Slack - 28 upvotes, $1000
410. [XSS in http://www.rockstargames.com/theballadofgaytony/js/jquery.base.js](https://hackerone.com/reports/242905) to Rockstar Games - 28 upvotes, $1000
411. [Stored Cross Site Scripting on Zendesk agent dashboard](https://hackerone.com/reports/394346) to Zendesk - 28 upvotes, $1000
412. [o2.mail.ru XSS](https://hackerone.com/reports/824666) to Mail.ru - 28 upvotes, $1000
413. [[XSS] Reflected XSS via POST request in (editJobAlert.htm) file](https://hackerone.com/reports/838910) to Glassdoor - 28 upvotes, $750
414. [[qiwi.com] XSS on payment form](https://hackerone.com/reports/263684) to QIWI - 28 upvotes, $550
415. [Reflected XSS at https://www.glassdoor.com/ via the 'numSuggestions' parameter](https://hackerone.com/reports/1042486) to Glassdoor - 28 upvotes, $500
416. [Reflected XSS in error pages (NC-SA-2017-008)](https://hackerone.com/reports/216812) to Nextcloud - 28 upvotes, $450
417. [Reflected XSS in www.dota2.com](https://hackerone.com/reports/292457) to Valve - 28 upvotes, $350
418. [Reflected XSS on the data.gov (WAF bypass+ Chrome XSS Auditor bypass+ works in all browsers)](https://hackerone.com/reports/265528) to GSA Bounty - 28 upvotes, $300
419. [[mercantile.wordpress.org] Reflected XSS via AngularJS Template Injection](https://hackerone.com/reports/230234) to WordPress - 28 upvotes, $300
420. [Persistent XSS via Signatures](https://hackerone.com/reports/413828) to Vanilla - 28 upvotes, $300
421. [[allhiphop.vanillacommunities.com] XSS Request-URI](https://hackerone.com/reports/386112) to Vanilla - 28 upvotes, $100
422. [XSS in (Support Requests) : User Cases](https://hackerone.com/reports/961226) to Acronis - 28 upvotes, $50
423. [Reflected XSS in www.olx.co.id](https://hackerone.com/reports/639796) to OLX - 28 upvotes, $0
424. [Reflected Xss](https://hackerone.com/reports/758854) to U.S. Dept Of Defense - 28 upvotes, $0
425. [Blind XSS on Twitter's internal Jira panel at ████ allows exfiltration of hackers reports and other sensitive data](https://hackerone.com/reports/1369674) to Twitter - 27 upvotes, $5040
426. [Stored XSS in group issue list](https://hackerone.com/reports/859333) to GitLab - 27 upvotes, $2000
427. [Stored XSS in snapmatic comments](https://hackerone.com/reports/231389) to Rockstar Games - 27 upvotes, $1000
428. [[web.icq.com] Stored XSS in "О Контакте"](https://hackerone.com/reports/547683) to Mail.ru - 27 upvotes, $500
429. [Reflected XSS at city-mobil.ru](https://hackerone.com/reports/797717) to Mail.ru - 27 upvotes, $300
430. [XSS in vk.link](https://hackerone.com/reports/1025125) to VK.com - 27 upvotes, $300
431. [HTTP Request Smuggling on api.flocktory.com Leads to XSS on Customer Sites](https://hackerone.com/reports/955170) to QIWI - 27 upvotes, $300
432. [DOM XSS in edoverflow.com/tools/respond due to unsafe usage of the innerHTML property.](https://hackerone.com/reports/341969) to Ed - 27 upvotes, $0
433. [CSS injection via BB code tag "█████"](https://hackerone.com/reports/587727) to phpBB - 27 upvotes, $0
434. [Preview bar: Incomplete message origin validation results in XSS](https://hackerone.com/reports/381192) to Shopify - 26 upvotes, $1000
435. [DOM based reflected XSS in rockstargames.com/newswire/tags through cross domain ajax request](https://hackerone.com/reports/172843) to Rockstar Games - 26 upvotes, $500
436. [Stored XSS in Macro Editing - Introduced by Admins to affect Admins](https://hackerone.com/reports/471660) to Zendesk - 26 upvotes, $500
437. [Bypass extension check leads to stored XSS at https://s2.booth.pm](https://hackerone.com/reports/1019425) to pixiv - 26 upvotes, $500
438. [Stored XSS in Satisfaction Surveys via "Ask Reason for Dissatisfaction" option](https://hackerone.com/reports/953791) to Lark Technologies - 26 upvotes, $500
439. [Persistent XSS at verkkopalvelu.tapiola.fi using spoofed React element and React v.0.13.3](https://hackerone.com/reports/139004) to LocalTapiola - 26 upvotes, $300
440. [[GitHub Extension] Unsanitised HTML leading to XSS on GitHub.com](https://hackerone.com/reports/220494) to Algolia - 26 upvotes, $200
441. [XSS Stored in Cacheable  response](https://hackerone.com/reports/1011093) to Acronis - 26 upvotes, $50
442. [Cloudflare based XSS for IE11](https://hackerone.com/reports/214620) to Cloudflare Vulnerability Disclosure - 26 upvotes, $0
443. [XSS Stored](https://hackerone.com/reports/205626) to Coursera - 26 upvotes, $0
444. [Cross-site Scripting (XSS) - DOM - iqcard.informatica.com](https://hackerone.com/reports/1004833) to Informatica - 26 upvotes, $0
445. [CSRF + XSS leads to ATO](https://hackerone.com/reports/1081148) to Mail.ru - 26 upvotes, $0
446. [Stored XSS on member post feed](https://hackerone.com/reports/264002) to Rockstar Games - 25 upvotes, $1000
447. [cross site scripting bypass session ](https://hackerone.com/reports/939158) to Mail.ru - 25 upvotes, $1000
448. [Cross Site Scripting using Email parameter in Ads endpoint 2](https://hackerone.com/reports/946160) to TikTok - 25 upvotes, $897
449. [WordPress core stored XSS via attachment file name](https://hackerone.com/reports/139245) to Automattic - 25 upvotes, $500
450. [Reflected XSS via #tags= while using a callback in newswire  http://www.rockstargames.com/newswire](https://hackerone.com/reports/153618) to Rockstar Games - 25 upvotes, $500
451. [XSS on https://www.starbucks.co.uk (can lead to credit card theft) (/shop/paymentmethod)](https://hackerone.com/reports/227486) to Starbucks - 25 upvotes, $500
452. [Stored xss в пересланном сообщении.](https://hackerone.com/reports/344228) to Mail.ru - 25 upvotes, $500
453. [Stored XSS in history on [corporate.city-mobil.ru]](https://hackerone.com/reports/952983) to Mail.ru - 25 upvotes, $300
454. [DOM XSS on app.starbucks.com via ReturnUrl](https://hackerone.com/reports/526265) to Starbucks - 25 upvotes, $250
455. [Self-XSS to Good-XSS - pornhub.com](https://hackerone.com/reports/761904) to Pornhub - 25 upvotes, $250
456. [XSS reflected on [https://www.youporn.com]](https://hackerone.com/reports/478530) to YouPorn - 25 upvotes, $150
457. [[intensedebate.com] XSS Reflected POST-Based on update/tumblr2/{$id}](https://hackerone.com/reports/1040639) to Automattic - 25 upvotes, $150
458. [Cross Site Scripting (Reflected) on https://www.acronis.cz/](https://hackerone.com/reports/1084156) to Acronis - 25 upvotes, $50
459. [Stored - XSS](https://hackerone.com/reports/532643) to Shopify - 25 upvotes, $0
460. [stored xss in app.lemlist.com](https://hackerone.com/reports/919859) to lemlist - 25 upvotes, $0
461. [Persistent XSS via e-mail when creating merge requests](https://hackerone.com/reports/496973) to GitLab - 24 upvotes, $750
462. [Reflected XSS в /al_audio.php](https://hackerone.com/reports/334691) to VK.com - 24 upvotes, $700
463. [Reflected XSS in /Videos/ via calling a callback http://www.rockstargames.com/videos/#/?lb=](https://hackerone.com/reports/151276) to Rockstar Games - 24 upvotes, $650
464. [[e.mail.ru] Stored xss in Mpop cookie](https://hackerone.com/reports/454401) to Mail.ru - 24 upvotes, $600
465. [XSS in touch.mail.ru ](https://hackerone.com/reports/409440) to Mail.ru - 24 upvotes, $500
466. [XSS via the lang parameter in a POST request on light.mail.ru](https://hackerone.com/reports/496128) to Mail.ru - 24 upvotes, $500
467. [Outdated Wordpress installation and plugins at www.uberxgermany.com create CSRF and XSS vulnerabilities](https://hackerone.com/reports/323899) to Uber - 24 upvotes, $500
468. [Stored XSS on Broken Themes via filename](https://hackerone.com/reports/406289) to WordPress - 24 upvotes, $300
469. [[tumblr.com] 69\< Firefox Only  XSS Reflected](https://hackerone.com/reports/915756) to Automattic - 24 upvotes, $250
470. [Authenticated Stored Cross-site Scripting in bbPress](https://hackerone.com/reports/881918) to WordPress - 24 upvotes, $225
471. [[growth.grab.com] Reflected XSS via Base64-encoded "q" param on "my.html" Valentine's microsite](https://hackerone.com/reports/320679) to Grab - 24 upvotes, $200
472. [Stored XSS in api.icq.net](https://hackerone.com/reports/363042) to Mail.ru - 24 upvotes, $150
473. [[stagecafrstore.starbucks.com] CRLF Injection, XSS](https://hackerone.com/reports/192667) to Starbucks - 24 upvotes, $0
474. [Stored XSS in Review Section https://games.mail.ru/](https://hackerone.com/reports/764935) to Mail.ru - 24 upvotes, $0
475. [Reflected XSS on /admin/stats.php](https://hackerone.com/reports/1083376) to Revive Adserver - 24 upvotes, $0
476. [Stored XSS in the banner block description](https://hackerone.com/reports/1065964) to Stripo Inc - 24 upvotes, $0
477. [Stored XSS on PyPi simple API endpoint](https://hackerone.com/reports/856836) to GitLab - 23 upvotes, $3000
478. [Stored DOM XSS via Mermaid chart](https://hackerone.com/reports/1103258) to GitLab - 23 upvotes, $3000
479. [Reflected cross-site scripting (XSS) on api.tiles.mapbox.com](https://hackerone.com/reports/135217) to Mapbox - 23 upvotes, $1000
480. [XSS в личных сообщениях](https://hackerone.com/reports/281851) to VK.com - 23 upvotes, $1000
481. [Blind stored xss in demo form](https://hackerone.com/reports/324194) to Upserve  - 23 upvotes, $500
482. [DOM Based XSS charting_library](https://hackerone.com/reports/351275) to Gatecoin - 23 upvotes, $500
483. [Wordpress 4.7.2 - Two XSS in Media Upload when file too large.](https://hackerone.com/reports/203515) to WordPress - 23 upvotes, $350
484. [Camo Image Proxy Bypass with CSS Escape Sequences](https://hackerone.com/reports/745953) to Chaturbate - 23 upvotes, $250
485. [XSS Reflected on my_report](https://hackerone.com/reports/491023) to Semrush - 23 upvotes, $200
486. [Persistent XSS via filename in projects](https://hackerone.com/reports/662204) to Nextcloud - 23 upvotes, $150
487. [Reflected XSS in the IE 11 / Edge (latest versions) on the stage-go.wepay.com](https://hackerone.com/reports/311467) to WePay - 23 upvotes, $100
488. [Reflected XSS on developers.zomato.com](https://hackerone.com/reports/418823) to Zomato - 23 upvotes, $100
489. [Stored Cross-Site-Scripting in CMS Airship's  authors profiles](https://hackerone.com/reports/148741) to Paragon Initiative Enterprises - 23 upvotes, $50
490. [Stored XSS in any message (leads to priv esc for all users and file leak + rce via electron app)](https://hackerone.com/reports/1014459) to Rocket.Chat - 23 upvotes, $0
491. [Stored XSS at Module Name](https://hackerone.com/reports/1126433) to Stripo Inc - 23 upvotes, $0
492. [Stored XSS on Share-popup of a directory's Gallery-view](https://hackerone.com/reports/145355) to Nextcloud - 22 upvotes, $750
493. [XSS via unicode characters in upload filename](https://hackerone.com/reports/179695) to WordPress - 22 upvotes, $600
494. [Universal Cross-Site Scripting in Keybase Chrome extension](https://hackerone.com/reports/232432) to Keybase - 22 upvotes, $500
495. [Admin bar: Incomplete message origin validation results in XSS](https://hackerone.com/reports/387544) to Shopify - 22 upvotes, $500
496. [Stored XSS on apps.shopify.com](https://hackerone.com/reports/1107726) to Shopify - 22 upvotes, $500
497. [Reflected XSS by exploiting CSRF vulnerability on teavana.com wishlist comment module. (wishlist-comments)](https://hackerone.com/reports/177508) to Starbucks - 22 upvotes, $375
498. [HTML injection leads to reflected XSS](https://hackerone.com/reports/743345) to Zomato - 22 upvotes, $150
499. [Reflected XSS on my.acronis.com](https://hackerone.com/reports/1168962) to Acronis - 22 upvotes, $50
500. [[newscdn.starbucks.com] CRLF Injection, XSS](https://hackerone.com/reports/192749) to Starbucks - 22 upvotes, $0
501. [Self DOM-Based XSS in www.hackerone.com](https://hackerone.com/reports/406587) to HackerOne - 22 upvotes, $0
502. [Stored XSS on oslo.io in notifications via project name change](https://hackerone.com/reports/1070859) to Logitech - 22 upvotes, $0
503. [Stored Cross-Site Scripting vulnerability in example Custom Digital Agreement](https://hackerone.com/reports/983077) to HackerOne - 22 upvotes, $0
504. [CSRF to Cross-site Scripting (XSS)](https://hackerone.com/reports/1118501) to U.S. Dept Of Defense - 22 upvotes, $0
505. [H1514 Stored XSS on Wholesale sales channel allows cross-organization data leakage](https://hackerone.com/reports/423454) to Shopify - 21 upvotes, $1000
506. [[Web ICQ Client] XSS уязвимость в имени пользователя](https://hackerone.com/reports/786822) to Mail.ru - 21 upvotes, $1000
507. [Stored XSS in e.mail.ru (payload affect multiple users)](https://hackerone.com/reports/217007) to Mail.ru - 21 upvotes, $750
508. [Xss Reflected On spgw.terrhq.ru [ url ]](https://hackerone.com/reports/582360) to Mail.ru - 21 upvotes, $750
509. [H1514 Stored XSS in Return Magic App portal content](https://hackerone.com/reports/420459) to Shopify - 21 upvotes, $750
510. [File Upload XSS in image uploading of App in mopub](https://hackerone.com/reports/97672) to Twitter - 21 upvotes, $560
511. [XSS on manually entering Postal codes](https://hackerone.com/reports/190951) to Shopify - 21 upvotes, $500
512. [Stored XSS in community.ubnt.com](https://hackerone.com/reports/179164) to Ubiquiti Inc. - 21 upvotes, $500
513. [Reflected XSS via Double Encoding](https://hackerone.com/reports/246505) to Rockstar Games - 21 upvotes, $500
514. [XSS / SELF XSS](https://hackerone.com/reports/906201) to Shopify - 21 upvotes, $500
515. [Reflected XSS в m.vk.com](https://hackerone.com/reports/311913) to VK.com - 21 upvotes, $500
516. [[render.bitstrips.com] Stored XSS via an incorrect avatar property value](https://hackerone.com/reports/159878) to Snapchat - 21 upvotes, $400
517. [Reflected Swf XSS In ( plugins.svn.wordpress.org )](https://hackerone.com/reports/270060) to WordPress - 21 upvotes, $350
518. [XSS Challenge](https://hackerone.com/reports/1027918) to BugPoC - 21 upvotes, $300
519. [Stored XSS in https://app.mopub.com](https://hackerone.com/reports/642281) to Twitter - 21 upvotes, $280
520. [DOM Based XSS In mercantile.wordpress.org](https://hackerone.com/reports/230435) to WordPress - 21 upvotes, $275
521. [XSS web.icq.com double linkify](https://hackerone.com/reports/348108) to Mail.ru - 21 upvotes, $250
522. [[icq.im] Reflected XSS via chat invite link](https://hackerone.com/reports/796897) to Mail.ru - 21 upvotes, $250
523. [xss filter bypass [polldaddy]](https://hackerone.com/reports/264832) to Automattic - 21 upvotes, $150
524. [XSS in zendesk.com/product/](https://hackerone.com/reports/141244) to Zendesk - 21 upvotes, $100
525. [Stored XSS in learnboost.com via the lesson[goals] parameter.](https://hackerone.com/reports/300270) to Automattic - 21 upvotes, $100
526. [[contact-sys.com] XSS /ajax/transfer/status trn param](https://hackerone.com/reports/164704) to QIWI - 21 upvotes, $100
527. [Blind Stored XSS on iOS App due to Unsanitized Webview](https://hackerone.com/reports/575562) to Nextcloud - 21 upvotes, $100
528. [XSS in PDF Viewer](https://hackerone.com/reports/819863) to Nextcloud - 21 upvotes, $100
529. [Potential XSS vulnerability to HTML minification](https://hackerone.com/reports/24684) to Cloudflare Vulnerability Disclosure - 21 upvotes, $0
530. [[takeapeek] XSS via HTML tag injection in directory lisiting page](https://hackerone.com/reports/490728) to Node.js third-party modules - 21 upvotes, $0
531. [XSS in messages on geekbrains.ru](https://hackerone.com/reports/623834) to Mail.ru - 21 upvotes, $0
532. [[kb.informatica.com] Dom Based xss](https://hackerone.com/reports/156166) to Informatica - 21 upvotes, $0
533. [Stored XSS on Zeit.co user profile](https://hackerone.com/reports/541737) to Vercel - 21 upvotes, $0
534. [Reflected XSS on https://go.mail.ru/search?fr=mn&q=\<payload\>](https://hackerone.com/reports/722977) to Mail.ru - 21 upvotes, $0
535. [Cross-site Scripting (XSS) - Reflected vseapteki.ru](https://hackerone.com/reports/409208) to Mail.ru - 21 upvotes, $0
536. [Solution for XSS challenge calc.buggywebsite.com](https://hackerone.com/reports/954249) to BugPoC - 21 upvotes, $0
537. [Reflected XSS in https://www.█████/](https://hackerone.com/reports/950700) to U.S. Dept Of Defense - 21 upvotes, $0
538. [Reflected XSS in https://www.██████/](https://hackerone.com/reports/924650) to U.S. Dept Of Defense - 21 upvotes, $0
539. [XSS :D](https://hackerone.com/reports/1026301) to BugPoC - 21 upvotes, $0
540. [Reflected XSS in https://www.topcoder.com/blog/category/community-stories/](https://hackerone.com/reports/1194301) to Topcoder - 21 upvotes, $0
541. [ add class vulnerable Stored XSS](https://hackerone.com/reports/1215179) to Mail.ru - 21 upvotes, $0
542. [Possibility to insert stored XSS inside \<img\> tag](https://hackerone.com/reports/267643) to Pornhub - 20 upvotes, $1500
543. [[FG-VD-18-165] Wordpress Cross-Site Scripting Vulnerability Notification II](https://hackerone.com/reports/460911) to WordPress - 20 upvotes, $650
544. [слепая XSS в админ панели torg.mail.ru через отзыв](https://hackerone.com/reports/366518) to Mail.ru - 20 upvotes, $500
545. [Stored blind xss on showmax support team](https://hackerone.com/reports/307485) to Showmax - 20 upvotes, $256
546. [Data URI Stored XSS on Donations Page](https://hackerone.com/reports/902336) to Mail.ru - 20 upvotes, $200
547. [Xss on community.imgur.com](https://hackerone.com/reports/274868) to Imgur - 20 upvotes, $50
548. [XSS in OAuth Redirect Url](https://hackerone.com/reports/163707) to Dropbox - 20 upvotes, $0
549. [[Markdown] Stored XSS via character encoding parser bypass](https://hackerone.com/reports/270999) to GitLab - 20 upvotes, $0
550. [Stored XSS in infogram.com via language ](https://hackerone.com/reports/430029) to Infogram - 20 upvotes, $0
551. [XSS in select attribute options](https://hackerone.com/reports/753567) to Concrete CMS - 20 upvotes, $0
552. [Stored Cross Site Scripting.](https://hackerone.com/reports/413077) to 8x8 - 20 upvotes, $0
553. [Stored XSS In mlbootcamp.ru](https://hackerone.com/reports/820217) to Mail.ru - 20 upvotes, $0
554. [XSS through image upload of contacts using svg file with png extension ](https://hackerone.com/reports/998422) to Nextcloud - 20 upvotes, $0
555. [CVE-2020-11110: Grafana Unauthenticated Stored XSS -████.bizml.ru](https://hackerone.com/reports/1329433) to Mail.ru - 20 upvotes, $0
556. [XSS vulnerability using GIF tags](https://hackerone.com/reports/191674) to Pornhub - 19 upvotes, $1000
557. [Stored XSS with CRLF injection via post message to user feed](https://hackerone.com/reports/263191) to Rockstar Games - 19 upvotes, $1000
558. [xss triggered in "myshopify.com/admin/product"](https://hackerone.com/reports/978125) to Shopify - 19 upvotes, $1000
559. [Stored XSS in calendar via UID parameter](https://hackerone.com/reports/758642) to Mail.ru - 19 upvotes, $1000
560. [Stored XSS in dropboxforum.com](https://hackerone.com/reports/413124) to Dropbox - 19 upvotes, $512
561. [Stored XSS in comments on https://www.starbucks.co.uk/blog/*](https://hackerone.com/reports/218226) to Starbucks - 19 upvotes, $500
562. [XSS in e.mail.ru](https://hackerone.com/reports/399382) to Mail.ru - 19 upvotes, $500
563. [Reflected xss в m.vk.com/chatjoin](https://hackerone.com/reports/1370240) to VK.com - 19 upvotes, $500
564. [Stored XSS in Application menu via Home Page Url](https://hackerone.com/reports/797754) to Ping Identity - 19 upvotes, $300
565. [Stored XSS in "post last edited" option](https://hackerone.com/reports/333507) to Discourse - 19 upvotes, $256
566. [Reflected xss on theacademy.upserve.com](https://hackerone.com/reports/415139) to Upserve  - 19 upvotes, $250
567. [Admin Macro Description Stored XSS](https://hackerone.com/reports/392457) to Zendesk - 19 upvotes, $250
568. [[parcel.grab.com] DOM XSS at /assets/bower_components/lodash/perf/](https://hackerone.com/reports/248560) to Grab - 19 upvotes, $200
569. [[*.rocketbank.ru] Web Cache Deception & XSS](https://hackerone.com/reports/415168) to QIWI - 19 upvotes, $200
570. [Solution to the XSS Challenge ](https://hackerone.com/reports/1026585) to BugPoC - 19 upvotes, $200
571. [Reflected XSS on a Atavist theme](https://hackerone.com/reports/947790) to Automattic - 19 upvotes, $150
572. [Reflected XSS via IE](https://hackerone.com/reports/892717) to Nord Security - 19 upvotes, $100
573. [reflected XSS avito.ru](https://hackerone.com/reports/344429) to Avito - 19 upvotes, $0
574. [Search Page Reflected XSS on sharjah.dubizzle.com through unencoded output of GET parameter in JavaScript](https://hackerone.com/reports/363571) to OLX - 19 upvotes, $0
575. [Reflected XSS ](https://hackerone.com/reports/732987) to OWOX, Inc. - 19 upvotes, $0
576. [[seeftl] Stored XSS when directory listing via filename.](https://hackerone.com/reports/665302) to Node.js third-party modules - 19 upvotes, $0
577. [XSS at go.mail.ru](https://hackerone.com/reports/846931) to Mail.ru - 19 upvotes, $0
578. [Reflected XSS on /admin/userlog-index.php](https://hackerone.com/reports/1083231) to Revive Adserver - 19 upvotes, $0
579. [Reflected XSS on ███](https://hackerone.com/reports/1057419) to U.S. Dept Of Defense - 19 upvotes, $0
580. [Blind XSS Stored and CORS misconfiguration в отчете "События" сервиса top.mail.ru](https://hackerone.com/reports/1255676) to Mail.ru - 19 upvotes, $0
581. [XSS vulnerability in sanitize-method when parsing link's href](https://hackerone.com/reports/328270) to Ruby on Rails - 18 upvotes, $1500
582. [reflected xss on the path m.tiktok.com](https://hackerone.com/reports/1394440) to TikTok - 18 upvotes, $1000
583. [Stored xss в /lead_forms_app.php](https://hackerone.com/reports/283539) to VK.com - 18 upvotes, $500
584. [XSS on https://account.mail.ru/login via postMessage](https://hackerone.com/reports/269349) to Mail.ru - 18 upvotes, $500
585. [XSS в выборе товара.](https://hackerone.com/reports/1253124) to VK.com - 18 upvotes, $500
586. [XSS on opening a malicious OpenOffice text document](https://hackerone.com/reports/894915) to Open-Xchange - 18 upvotes, $400
587. [Blind Stored XSS In  "Report a Problem" on www.data.gov/issue/](https://hackerone.com/reports/615840) to GSA Bounty - 18 upvotes, $300
588. [XSS in the search bar of mercantile.wordpress.org](https://hackerone.com/reports/221893) to WordPress - 18 upvotes, $275
589. [Stored xss in ALBUM DESCRIPTION ](https://hackerone.com/reports/181955) to Imgur - 18 upvotes, $250
590. [Cross-Site Scripting Reflected On Main Domain](https://hackerone.com/reports/104917) to Instacart - 18 upvotes, $100
591. [XSS at in instacart.com/store/partner_recipe](https://hackerone.com/reports/227809) to Instacart - 18 upvotes, $100
592. [Reflected XSS using Header Injection](https://hackerone.com/reports/297203) to Semrush - 18 upvotes, $100
593. [XSS through image upload of contacts using svg file](https://hackerone.com/reports/894876) to Nextcloud - 18 upvotes, $100
594. [DOM XSS on 1.1.1.1(one.one.one.one)](https://hackerone.com/reports/418078) to Cloudflare Vulnerability Disclosure - 18 upvotes, $0
595. [XSS Reflected at SEARCH \>\>](https://hackerone.com/reports/429647) to OLX - 18 upvotes, $0
596. [Reflected XSS on https://apps.topcoder.com/wiki/page/](https://hackerone.com/reports/866433) to Topcoder - 18 upvotes, $0
597. [XSS (reflected, and then, cookie persisted)  on api documentation site theme selector (old version of dokuwiki)](https://hackerone.com/reports/1066502) to Mail.ru - 18 upvotes, $0
598. [Self stored Xss + Login Csrf](https://hackerone.com/reports/1092678) to U.S. Dept Of Defense - 18 upvotes, $0
599. [Stored XSS on newsroom.uber.com admin panel / Stream WordPress plugin](https://hackerone.com/reports/127948) to Uber - 17 upvotes, $5000
600. [Stored XSS firing at transaction map (applicationName field)](https://hackerone.com/reports/549084) to New Relic - 17 upvotes, $2500
601. [XSS on partners.uber.com due to no user input sanitisation ](https://hackerone.com/reports/281283) to Uber - 17 upvotes, $1000
602. [[Web ICQ Client] XSS-inj in polls](https://hackerone.com/reports/785785) to Mail.ru - 17 upvotes, $1000
603. [Reflected XSS in reddeadredemption Site  located at www.rockstargames.com/reddeadredemption](https://hackerone.com/reports/149673) to Rockstar Games - 17 upvotes, $750
604. [[IMP] - Blind XSS in the admin panel for reviewing comments](https://hackerone.com/reports/197337) to Rockstar Games - 17 upvotes, $650
605. [Хранимая XSS в группе VK](https://hackerone.com/reports/266072) to VK.com - 17 upvotes, $500
606. [Stealing app credentials by reflected xss on Lark Suite](https://hackerone.com/reports/791278) to Lark Technologies - 17 upvotes, $500
607. [Reflected XSS on molpay.com with cloudflare bypass](https://hackerone.com/reports/800360) to Razer - 17 upvotes, $375
608. [OX (Guard): Stored Cross-Site Scripting via Email Attachment](https://hackerone.com/reports/165275) to Open-Xchange - 17 upvotes, $300
609. [stored xss in comments : driver exam ](https://hackerone.com/reports/274443) to Grab - 17 upvotes, $250
610. [Reflected XSS on https://www.easytopup.in.th/store/product/return on parameter mref_id](https://hackerone.com/reports/776883) to Razer - 17 upvotes, $250
611. [[nutty.ubnt.com] DOM Based XSS nuttyapp github-btn.html](https://hackerone.com/reports/200753) to Ubiquiti Inc. - 17 upvotes, $100
612. [DOM-based XSS in store.starbucks.co.uk on IE 11](https://hackerone.com/reports/241619) to Starbucks - 17 upvotes, $100
613. [Stored XSS on chaturbate.com (wish list)](https://hackerone.com/reports/425048) to Chaturbate - 17 upvotes, $100
614. [[wallet.rapida.ru] XSS Cookie flashcookie](https://hackerone.com/reports/164662) to QIWI - 17 upvotes, $100
615. [Reflected XSS / Markup Injection in `index.php/svg/core/logo/logo` parameter `color`](https://hackerone.com/reports/605915) to Nextcloud - 17 upvotes, $50
616. [DOM based XSS in store.acronis.com/\<id\>/purl-corporate-standard-IT [cfg parameter]](https://hackerone.com/reports/968690) to Acronis - 17 upvotes, $50
617. [Persistent XSS found on bin.pinion.gg due to outdated FlowPlayer SWF file with Remote File Inclusion vulnerability.](https://hackerone.com/reports/254269) to Unikrn - 17 upvotes, $30
618. [Store XSS on Informatica University via transcript (informatica.csod.com)](https://hackerone.com/reports/219509) to Informatica - 17 upvotes, $0
619. [Reflected XSS vulnerability in Database name field on installation screen](https://hackerone.com/reports/289330) to Concrete CMS - 17 upvotes, $0
620. [Cross Site Scripting -\> Reflected XSS](https://hackerone.com/reports/150568) to OLX - 17 upvotes, $0
621. [Reflected XSS ](https://hackerone.com/reports/267206) to Informatica - 17 upvotes, $0
622. [Stored XSS in merge request pages](https://hackerone.com/reports/409380) to GitLab - 17 upvotes, $0
623. [Self XSS combine CSRF at https://████████/index.php](https://hackerone.com/reports/485684) to U.S. Dept Of Defense - 17 upvotes, $0
624. [XSS Reflect to POST █████](https://hackerone.com/reports/1003433) to U.S. Dept Of Defense - 17 upvotes, $0
625. [Probably unexploitable XSS via Header Injection](https://hackerone.com/reports/836689) to WHO COVID-19 Mobile App - 17 upvotes, $0
626. [Stored XSS on 1.4.0](https://hackerone.com/reports/1331281) to ImpressCMS - 17 upvotes, $0
627. [Reflected XSS on dailydeals.mtn.co.za](https://hackerone.com/reports/1212235) to MTN Group - 17 upvotes, $0
628. [New experimental query: Clipboard-based XSS](https://hackerone.com/reports/1345484) to GitHub Security Lab - 16 upvotes, $4500
629. [XSS on OAuth authorize/authenticate endpoint](https://hackerone.com/reports/87040) to Twitter - 16 upvotes, $2520
630. [Stored XSS firing at the "Add chart to note" popup](https://hackerone.com/reports/566400) to New Relic - 16 upvotes, $2500
631. [XSS on vimeo.com/home after other user follows you](https://hackerone.com/reports/87854) to Vimeo - 16 upvotes, $1500
632. [XSS в товарах](https://hackerone.com/reports/273365) to VK.com - 16 upvotes, $1000
633. [Stored XSS via Send crew invite](https://hackerone.com/reports/272997) to Rockstar Games - 16 upvotes, $1000
634. [XSS в теле письма.](https://hackerone.com/reports/303727) to Mail.ru - 16 upvotes, $1000
635. [Reflected XSS](https://hackerone.com/reports/304175) to Ubiquiti Inc. - 16 upvotes, $1000
636. [Reflected XSS on https://e.mail.ru/compose/ via Body parameter](https://hackerone.com/reports/1000363) to Mail.ru - 16 upvotes, $1000
637. [Stored XSS in files.slack.com](https://hackerone.com/reports/827606) to Slack - 16 upvotes, $1000
638. [Dom based xss on https://www.rockstargames.com/ via `returnUrl` parameter](https://hackerone.com/reports/505157) to Rockstar Games - 16 upvotes, $750
639. [Blind Stored XSS](https://hackerone.com/reports/347215) to Mail.ru - 16 upvotes, $550
640. [XSS on www.mapbox.com/authorize/ because of open redirect at /core/oauth/auth](https://hackerone.com/reports/143240) to Mapbox - 16 upvotes, $500
641. [stored xss in invited team member via email parameter](https://hackerone.com/reports/267177) to Shopify - 16 upvotes, $500
642. [XSS in e.mail.ru](https://hackerone.com/reports/419872) to Mail.ru - 16 upvotes, $500
643. [Reflected XSS in https://eng.uberinternal.com and https://coeshift.corp.uber.internal/](https://hackerone.com/reports/354686) to Uber - 16 upvotes, $500
644. [Reflected XSS at https://www.glassdoor.com/Interview/Accenturme-Interview-Questions-E9931.htm  via  filter.jobTitleFTS  parameter](https://hackerone.com/reports/995936) to Glassdoor - 16 upvotes, $500
645. [Reflected XSS at https://da.wordpress.org/themes/?s= via "s=" parameter ](https://hackerone.com/reports/222040) to WordPress - 16 upvotes, $387
646. [[controlsyou.quora.com] 429 Too Many Requests Error-Page XSS](https://hackerone.com/reports/189768) to Quora - 16 upvotes, $300
647. [DOM XSS vulnerability in search dialogue (NC-SA-2017-007)](https://hackerone.com/reports/213227) to Nextcloud - 16 upvotes, $250
648. [Stored XSS in dev-ucrm-billing-demo.ubnt.com In Client Custom Attribute ](https://hackerone.com/reports/275515) to Ubiquiti Inc. - 16 upvotes, $250
649. [[app.simplenote.com] Stored XSS via Markdown SVG filter bypass](https://hackerone.com/reports/271007) to Automattic - 16 upvotes, $200
650. [Stored XSS](https://hackerone.com/reports/157958) to Instacart - 16 upvotes, $150
651. [Stored XSS на странице "Измененить водителя" [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1050030) to Mail.ru - 16 upvotes, $150
652. [Stored XSS на странице "Изменить клиента", вкладка "История" [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1050047) to Mail.ru - 16 upvotes, $150
653. [Stored XSS in www.learnboost.com via ZIP codes.](https://hackerone.com/reports/300812) to Automattic - 16 upvotes, $100
654. [XSS on https://www.delivery-club.ru](https://hackerone.com/reports/316897) to Mail.ru - 16 upvotes, $100
655. [XSS in desktop client via invalid server address on login form](https://hackerone.com/reports/685552) to Nextcloud - 16 upvotes, $100
656. [Reflected XSS when renaming a file with a vulnerable name which results in an error](https://hackerone.com/reports/896522) to Nextcloud - 16 upvotes, $100
657. [Stored XSS at https://finance.owox.com/customer/accountList](https://hackerone.com/reports/192922) to OWOX, Inc. - 16 upvotes, $0
658. [Stored XSS on Files overview by abusing git submodule URL](https://hackerone.com/reports/218872) to GitLab - 16 upvotes, $0
659. [[airbnb.com] XSS via Cookie flash](https://hackerone.com/reports/197334) to Airbnb - 16 upvotes, $0
660. [Authenticated reflected XSS on liberapay.com via the back_to parameter when leaving a team.](https://hackerone.com/reports/360797) to Liberapay - 16 upvotes, $0
661. [Blind XSS in the rocket.chat registration email](https://hackerone.com/reports/382666) to Rocket.Chat - 16 upvotes, $0
662. [DOM XSS on 50x.html page](https://hackerone.com/reports/405191) to DuckDuckGo - 16 upvotes, $0
663. [Cross Site Scripting at https://app.oberlo.com/](https://hackerone.com/reports/542258) to Shopify - 16 upvotes, $0
664. [BUG XSS IN "ADD IMAGES"](https://hackerone.com/reports/583710) to Imgur - 16 upvotes, $0
665. [Reflected XSS on /www/delivery/afr.php (bypass of report #775693)](https://hackerone.com/reports/986365) to Revive Adserver - 16 upvotes, $0
666. [Reflected XSS on https://█████████/](https://hackerone.com/reports/1065167) to U.S. Dept Of Defense - 16 upvotes, $0
667. [Reflected XSS on mtnhottseat.mtn.com.gh](https://hackerone.com/reports/1069527) to MTN Group - 16 upvotes, $0
668. [XSS @ love.uber.com](https://hackerone.com/reports/117068) to Uber - 15 upvotes, $3000
669. [Stored XSS via "my recent queries" selector in NRQL dashboard builder](https://hackerone.com/reports/626082) to New Relic - 15 upvotes, $2500
670. [Stored XSS on {https://calendar.mail.ru/}](https://hackerone.com/reports/837215) to Mail.ru - 15 upvotes, $1000
671. [Multiple Cross-Site Scripting vulnerability via the language parameter](https://hackerone.com/reports/953053) to TikTok - 15 upvotes, $897
672. [XSS on postal codes](https://hackerone.com/reports/192140) to Shopify - 15 upvotes, $500
673. [DOM XSS via Shopify.API.remoteRedirect](https://hackerone.com/reports/576532) to Shopify - 15 upvotes, $500
674. [XSS на странице account.mail.ru/recovery](https://hackerone.com/reports/381762) to Mail.ru - 15 upvotes, $500
675. [Another Stored XSS in mail app using Drive app](https://hackerone.com/reports/538632) to Open-Xchange - 15 upvotes, $500
676. [Хранимая XSS в личных сообщениях новое место](https://hackerone.com/reports/310339) to ok.ru - 15 upvotes, $500
677. [Reflected XSS at https://sea-web.gold.razer.com/cash-card/verify via channel parameter](https://hackerone.com/reports/769086) to Razer - 15 upvotes, $500
678. [Reflected XSS at  https://www.glassdoor.co.in/Interview/BlackRock-Interview-Questions-E9331.htm via filter.jobTitleExact parameter](https://hackerone.com/reports/966527) to Glassdoor - 15 upvotes, $500
679. [XSS - Search - Unescaped contact job](https://hackerone.com/reports/993222) to Open-Xchange - 15 upvotes, $450
680. [Html Injection and Possible XSS in main nordvpn.com domain](https://hackerone.com/reports/780632) to Nord Security - 15 upvotes, $400
681. [Stored XSS on invoice, executing on any subdomain](https://hackerone.com/reports/152591) to Harvest - 15 upvotes, $350
682. [Authenticated Cross-site Scripting in Template Name](https://hackerone.com/reports/220903) to WordPress - 15 upvotes, $350
683. [Double Stored Cross-Site scripting in the admin panel](https://hackerone.com/reports/245172) to GSA Bounty - 15 upvotes, $300
684. [Reflected XSS: Taxonomy Converter via tax parameter](https://hackerone.com/reports/495515) to WordPress - 15 upvotes, $275
685. [xss in Theme http://bztfashion.booztx.com](https://hackerone.com/reports/166694) to Boozt Fashion AB - 15 upvotes, $250
686. [DOM XSS on teavana.com via "pr_zip_location" parameter](https://hackerone.com/reports/209736) to Starbucks - 15 upvotes, $250
687. [Reflected XSS on teavana.com (Locale-Change)](https://hackerone.com/reports/190798) to Starbucks - 15 upvotes, $250
688. [Mobile Reflect XSS / CSRF at Advertisement Section on Search page](https://hackerone.com/reports/379705) to Pornhub - 15 upvotes, $200
689. [Dom Based Xss DIV.innerHTML  parameters store.starbucks*](https://hackerone.com/reports/188185) to Starbucks - 15 upvotes, $150
690. [[ibank.qiwi.ru] XSS via Request-URI](https://hackerone.com/reports/164152) to QIWI - 15 upvotes, $150
691. [Cross-site Scripting (XSS) - Stored in ru.mail.mailapp](https://hackerone.com/reports/544782) to Mail.ru - 15 upvotes, $150
692. [Reflected XSS at /category/ on a Atavis theme ](https://hackerone.com/reports/950845) to Automattic - 15 upvotes, $150
693. [Stored XSS на странице "Изменить клиента" [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1050022) to Mail.ru - 15 upvotes, $150
694. [XSS in instacart.com/store/partner_recipe](https://hackerone.com/reports/196221) to Instacart - 15 upvotes, $100
695. [XSS when clicking "Share to Twitter" at quora.com/widgets/embed_iframe?path=...](https://hackerone.com/reports/258876) to Quora - 15 upvotes, $100
696. [Stored CSS Injection](https://hackerone.com/reports/315865) to Coinbase - 15 upvotes, $100
697. [[sms.qiwi.ru] XSS via Request-URI](https://hackerone.com/reports/38345) to QIWI - 15 upvotes, $100
698. [Content-type sniffing leads to stored XSS in CMS Airship on Internet Explorer ](https://hackerone.com/reports/151231) to Paragon Initiative Enterprises - 15 upvotes, $0
699. [Stored XSS](https://hackerone.com/reports/214484) to Mail.ru - 15 upvotes, $0
700. [XSS on pornhubselect.com](https://hackerone.com/reports/222556) to Pornhub - 15 upvotes, $0
701. [Reflective XSS at olx.ph](https://hackerone.com/reports/361647) to OLX - 15 upvotes, $0
702. [Stored XSS on Issue details page](https://hackerone.com/reports/384255) to GitLab - 15 upvotes, $0
703. [Reflected XSS  in the npm module express-cart.](https://hackerone.com/reports/395944) to Node.js third-party modules - 15 upvotes, $0
704. [Reflected XSS on http://info.ucs.ru/settings/check/](https://hackerone.com/reports/901064) to Mail.ru - 15 upvotes, $0
705. [Cross Site Scripting (XSS) Stored - Private messaging](https://hackerone.com/reports/768313) to Concrete CMS - 15 upvotes, $0
706. [XSS in message attachment fileds.](https://hackerone.com/reports/899954) to Rocket.Chat - 15 upvotes, $0
707. [Blind stored XSS due to insecure contact form at https://█████.mil leads to leakage of session token and ](https://hackerone.com/reports/1036877) to U.S. Dept Of Defense - 15 upvotes, $0
708. [xss vulnerability in http://ubermovement.com/community/daniel](https://hackerone.com/reports/142946) to Uber - 14 upvotes, $750
709. [Blind XSS in mapbox.com/contact](https://hackerone.com/reports/158461) to Mapbox - 14 upvotes, $750
710. [Dom based xss on /reddeadredemption2/br/videos](https://hackerone.com/reports/488108) to Rockstar Games - 14 upvotes, $750
711. [Reflected XSS at https://www.glassdoor.co.in/Job/pratt-whitney-jobs-SRCH_KE0,13.htm?initiatedFromCountryPicker=true&countryRedirect=true](https://hackerone.com/reports/971304) to Glassdoor - 14 upvotes, $550
712. [Unauthenticated Stored XSS on \<any\>.myshopify.com via checkout page](https://hackerone.com/reports/189378) to Shopify - 14 upvotes, $500
713. [Reflected Cross-Site Scripting due to vulnerable Flash component (Flashmediaelement.swf)](https://hackerone.com/reports/180253) to Open-Xchange - 14 upvotes, $500
714. [Stored XSS in the any user profile using website link](https://hackerone.com/reports/242213) to Pornhub - 14 upvotes, $500
715. [XSS в приглашении в группу](https://hackerone.com/reports/269940) to VK.com - 14 upvotes, $500
716. [Stored XSS in partners dashboard](https://hackerone.com/reports/271765) to Shopify - 14 upvotes, $500
717. [Self XSS in Timeline ](https://hackerone.com/reports/854299) to Shopify - 14 upvotes, $500
718. [XSS - Notes - Attribute injection through overlapping tags](https://hackerone.com/reports/995273) to Open-Xchange - 14 upvotes, $450
719. [xss reflected in littleguy.vanillastaging.com](https://hackerone.com/reports/321420) to Vanilla - 14 upvotes, $300
720. [XSS using javascript:alert(8007)](https://hackerone.com/reports/127154) to Twitter - 14 upvotes, $280
721. [Stored self-XSS in mercantile.wordpress.org checkout](https://hackerone.com/reports/230232) to WordPress - 14 upvotes, $275
722. [Buddypress 2.9.1 - Exceeding the maximum upload size  - XSS leading to potential RCE. ](https://hackerone.com/reports/263109) to WordPress - 14 upvotes, $275
723. [XSS vulnerability on Audio and Video parsers](https://hackerone.com/reports/192223) to Discourse - 14 upvotes, $256
724. [XSS Vulnerability on Image link parser](https://hackerone.com/reports/191909) to Discourse - 14 upvotes, $256
725. [XSS в нике при запросе в контакты.](https://hackerone.com/reports/321643) to Mail.ru - 14 upvotes, $250
726. [XSS при добавлении в чат пользователя ](https://hackerone.com/reports/339137) to Mail.ru - 14 upvotes, $250
727. [XSS in main search, use class tag to imitate Reverb.com core functionality, create false login window](https://hackerone.com/reports/351376) to Reverb.com - 14 upvotes, $150
728. [Reflected XSS on a Atavist theme at external_import.php](https://hackerone.com/reports/976657) to Automattic - 14 upvotes, $150
729. [XSS при Изменения машины на странице "Контроль" [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1061439) to Mail.ru - 14 upvotes, $150
730. [Reflected XSS](https://hackerone.com/reports/203241) to Algolia - 14 upvotes, $100
731. [[github.algolia.com] DOM Based XSS github-btn.html](https://hackerone.com/reports/200826) to Algolia - 14 upvotes, $100
732. [Reflected XSS on https://www.zomato.com](https://hackerone.com/reports/311639) to Zomato - 14 upvotes, $100
733. [Reflected XSS on https://www.delivery-club.ru/](https://hackerone.com/reports/316898) to Mail.ru - 14 upvotes, $100
734. [[contact-sys.com] XSS via Request-URI](https://hackerone.com/reports/164656) to QIWI - 14 upvotes, $100
735. [Reflected Flash XSS using swfupload.swf with an epileptic reloading to bypass the button-event](https://hackerone.com/reports/91421) to Imgur - 14 upvotes, $50
736. [Cross-site Scripting (XSS) on [maximum.nl] ](https://hackerone.com/reports/228006) to Radancy - 14 upvotes, $50
737. [Unauthenticated Stored xss ](https://hackerone.com/reports/168054) to Nextcloud - 14 upvotes, $0
738. [XSS @ *.letgo.com](https://hackerone.com/reports/150822) to OLX - 14 upvotes, $0
739. [Big XSS vulnerability!](https://hackerone.com/reports/216330) to Legal Robot - 14 upvotes, $0
740. [POST XSS  in https://www.khanacademy.org.tr/ via page_search_query parameter](https://hackerone.com/reports/382321) to Khan Academy - 14 upvotes, $0
741. [Cross site scripting vulnerability in JW Player SWF](https://hackerone.com/reports/496883) to Mail.ru - 14 upvotes, $0
742. [XSS on www.██████ alerts and a number of other pages](https://hackerone.com/reports/450315) to U.S. Dept Of Defense - 14 upvotes, $0
743. [[█████] — DOM-based XSS on endpoint `/?s=`](https://hackerone.com/reports/708592) to U.S. Dept Of Defense - 14 upvotes, $0
744. [Reflected XSS on www/delivery/afr.php](https://hackerone.com/reports/775693) to Revive Adserver - 14 upvotes, $0
745. [Reflected XSS on am.ru and subdomains](https://hackerone.com/reports/799056) to Mail.ru - 14 upvotes, $0
746. [Reflected cross-site scripting vulnerability on a DoD website](https://hackerone.com/reports/774792) to U.S. Dept Of Defense - 14 upvotes, $0
747. [Stored XSS at [ https://app.lemlist.com/campaigns/cam_QRS5caF2ca7MJtiLS/leads ] in " LINKEDIN URL" Field.](https://hackerone.com/reports/932557) to lemlist - 14 upvotes, $0
748. [XSS Challenge #2 Solution](https://hackerone.com/reports/953873) to BugPoC - 14 upvotes, $0
749. [XSS In https://docs.gocd.org/current/](https://hackerone.com/reports/1033832) to GoCD - 14 upvotes, $0
750. [Download full backup and Cross site scripting ](https://hackerone.com/reports/1049040) to ImpressCMS - 14 upvotes, $0
751. [Reflected XSS on https://deti.mail.ru](https://hackerone.com/reports/1110927) to Mail.ru - 14 upvotes, $0
752. [XSS via X-Forwarded-Host header](https://hackerone.com/reports/882220) to U.S. Dept Of Defense - 14 upvotes, $0
753. [Reflected XSS at dailydeals.mtn.co.za](https://hackerone.com/reports/1210921) to MTN Group - 14 upvotes, $0
754. [Stored XSS at APM applications listing](https://hackerone.com/reports/530511) to New Relic - 13 upvotes, $2500
755. [Stored XSS at APM key transactions list](https://hackerone.com/reports/567468) to New Relic - 13 upvotes, $2500
756. [Cross-site scripting on the main page of flickr by tagging a user.](https://hackerone.com/reports/916) to Yahoo! - 13 upvotes, $2173
757. [XSS в теле письма, в новой версии почты.](https://hackerone.com/reports/369201) to Mail.ru - 13 upvotes, $1000
758. [SocialClub's Facebook OAuth Theft through Warehouse XSS.](https://hackerone.com/reports/316948) to Rockstar Games - 13 upvotes, $750
759. [Reflected XSS on help.steampowered.com](https://hackerone.com/reports/390429) to Valve - 13 upvotes, $750
760. [Stored XSS in Post Preview as Contributor](https://hackerone.com/reports/497724) to WordPress - 13 upvotes, $650
761. [[www.dropboxforum.com] - reflected XSS in search](https://hackerone.com/reports/413599) to Dropbox - 13 upvotes, $512
762. [Stored XSS in *.myshopify.com](https://hackerone.com/reports/241008) to Shopify - 13 upvotes, $500
763. [Reflected XSS via XML Namespace URI on https://go.mapbox.com/index.php/soap/](https://hackerone.com/reports/780277) to Mapbox - 13 upvotes, $500
764. [[m.vk.com] XSS на страницах /artist/ ](https://hackerone.com/reports/874198) to VK.com - 13 upvotes, $500
765. [Stored xss on helpdesk using user's city](https://hackerone.com/reports/971857) to Lark Technologies - 13 upvotes, $500
766. [Mixed Reflected-Stored XSS on pornhub.com (without user interaction) in the playlist playing section](https://hackerone.com/reports/222506) to Pornhub - 13 upvotes, $350
767. [[chatws25.stream.highwebmedia.com] - Reflected XSS in c parameter](https://hackerone.com/reports/413442) to Chaturbate - 13 upvotes, $350
768. [Content Injection on api.semrush.com to Reflected XSS](https://hackerone.com/reports/752042) to Semrush - 13 upvotes, $350
769. [Stored XSS in Rich editor via Embed datetime](https://hackerone.com/reports/530458) to Vanilla - 13 upvotes, $300
770. [[okmedia.insideok.ru] Web Cache Poisoing & XSS](https://hackerone.com/reports/550266) to ok.ru - 13 upvotes, $300
771. [XSS in topics because of bandcamp preview engine vulnerability](https://hackerone.com/reports/197443) to Discourse - 13 upvotes, $256
772. [Stored XSS in topics because of whitelisted_generic engine vulnerability](https://hackerone.com/reports/197902) to Discourse - 13 upvotes, $256
773. [XSS on expenses attachments](https://hackerone.com/reports/165324) to Harvest - 13 upvotes, $250
774. [DOM-based XSS on youporn.com (main page)](https://hackerone.com/reports/221883) to YouPorn - 13 upvotes, $250
775. [[mercantile.wordpress.org] Reflected XSS](https://hackerone.com/reports/240256) to WordPress - 13 upvotes, $225
776. [XSS in buying and selling pages, can created spoofed content (false login message)](https://hackerone.com/reports/353293) to Reverb.com - 13 upvotes, $200
777. [Stored XSS в профиле водителя [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1050017) to Mail.ru - 13 upvotes, $150
778. [Stored XSS на странице "Почты" [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1050054) to Mail.ru - 13 upvotes, $150
779. [XSS на странице "Создать водителя" [city-mobil.ru/taxiserv]](https://hackerone.com/reports/1057971) to Mail.ru - 13 upvotes, $150
780. [XSS at https://app.goodhire.com/member/GH.aspx](https://hackerone.com/reports/239762) to Inflection - 13 upvotes, $100
781. [Zomato.com Reflected Cross Site Scripting](https://hackerone.com/reports/303522) to Zomato - 13 upvotes, $100
782. [lootdog.io XSS](https://hackerone.com/reports/343752) to Mail.ru - 13 upvotes, $100
783. [XSS on redirection page( Bypassed) ](https://hackerone.com/reports/316319) to Semrush - 13 upvotes, $100
784. [self-xss with ClickJacking can leads to account takeover in Firefox](https://hackerone.com/reports/892289) to Imgur - 13 upvotes, $100
785. [xss reflected on imgur.com](https://hackerone.com/reports/1058427) to Imgur - 13 upvotes, $100
786. [Stored XSS in Name of Team Member Invitation](https://hackerone.com/reports/786301) to Localize - 13 upvotes, $50
787. [Cross-site Scripting (XSS) - Stored | forum.acronis.com](https://hackerone.com/reports/1161241) to Acronis - 13 upvotes, $50
788. [Persistent XSS on public wiki pages](https://hackerone.com/reports/136333) to GitLab - 13 upvotes, $0
789. [Unauthenticated Reflected XSS in admin dashboard](https://hackerone.com/reports/297434) to Deconf - 13 upvotes, $0
790. [3rd party shop admin panel blind XSS](https://hackerone.com/reports/336145) to Mail.ru - 13 upvotes, $0
791. [Stored Cross-site scripting ](https://hackerone.com/reports/541710) to Vercel - 13 upvotes, $0
792. [Unrestricted File Upload To Xss Stored [ https://ideas.browser.mail.ru/ ]](https://hackerone.com/reports/603788) to Mail.ru - 13 upvotes, $0
793. [[geekbrains.ru] Reflected XSS via Angular Template Injection](https://hackerone.com/reports/792847) to Mail.ru - 13 upvotes, $0
794. [Blind stored XSS due to insecure contact form at https://www.topcoder.com leads to leakage of session token and other PII](https://hackerone.com/reports/878145) to Topcoder - 13 upvotes, $0
795. [DOM Based XSS on https://████ via backURL param](https://hackerone.com/reports/1159255) to U.S. Dept Of Defense - 13 upvotes, $0
796. [DOM XSS through ads](https://hackerone.com/reports/889041) to Urban Dictionary - 13 upvotes, $0
797. [Reflected Xss in https://world.engelvoelkers.com/...](https://hackerone.com/reports/1401209) to Engel & Völkers Technology GmbH - 13 upvotes, $0
798. [Store XSS Flicker main page](https://hackerone.com/reports/940) to Yahoo! - 12 upvotes, $1960
799. [XSS в письме, в поле отправителя.](https://hackerone.com/reports/246634) to Mail.ru - 12 upvotes, $1000
800. [Triggering RCE using XSS to bypass CSRF in PowerBeam M5 300](https://hackerone.com/reports/289264) to Ubiquiti Inc. - 12 upvotes, $1000
801. [XSS @ store.steampowered.com via agecheck path name](https://hackerone.com/reports/406704) to Valve - 12 upvotes, $750
802. [DOM BASED XSS ON https://www.rockstargames.com/GTAOnline/features ](https://hackerone.com/reports/479612) to Rockstar Games - 12 upvotes, $750
803. [XSS Yahoo Messenger Via Calendar.Yahoo.Com ](https://hackerone.com/reports/914) to Yahoo! - 12 upvotes, $677
804. [xss in link items (mopub.com)](https://hackerone.com/reports/100931) to Twitter - 12 upvotes, $560
805. [XSS in SHOPIFY: Unsanitized Supplier Name  can lead to XSS in Transfers Timeline](https://hackerone.com/reports/167075) to Shopify - 12 upvotes, $500
806. [Stored XSS at 'Buy Button' page](https://hackerone.com/reports/186462) to Shopify - 12 upvotes, $500
807. [Blind Stored XSS against Pornhub employees using Amateur Model Program](https://hackerone.com/reports/216379) to Pornhub - 12 upvotes, $500
808. [XSS on www.mapbox.com/authorize](https://hackerone.com/reports/143220) to Mapbox - 12 upvotes, $500
809. [reflected XSS on healt.mail.ru](https://hackerone.com/reports/276714) to Mail.ru - 12 upvotes, $500
810. [OX Guard: DOM Based Cross-Site Scripting (#2)](https://hackerone.com/reports/164821) to Open-Xchange - 12 upvotes, $500
811. [XSS due to incomplete JS escaping](https://hackerone.com/reports/474262) to Ruby on Rails - 12 upvotes, $500
812. [Reflected XSS and Open Redirect in several parameters (viestinta.lahitapiola.fi)](https://hackerone.com/reports/191387) to LocalTapiola - 12 upvotes, $450
813. [Open redirect / Reflected XSS payload in root that affects all your sites (store.starbucks.* / shop.starbucks.* / teavana.com)](https://hackerone.com/reports/196846) to Starbucks - 12 upvotes, $375
814. [Post Based Reflected XSS on [https://investor.razer.com/s/ir_contact.php]](https://hackerone.com/reports/801075) to Razer - 12 upvotes, $375
815. [[bbPress] Stored XSS in any forum post.](https://hackerone.com/reports/151117) to Automattic - 12 upvotes, $300
816. [reflected xss on learn.city-mobil.ru via redirect_url parameter](https://hackerone.com/reports/1027962) to Mail.ru - 12 upvotes, $300
817. [Lazy Load stored XSS](https://hackerone.com/reports/152416) to Automattic - 12 upvotes, $275
818. [Stored XSS in posts because of absence of oembed variables values escaping](https://hackerone.com/reports/197914) to Discourse - 12 upvotes, $256
819. [Stored XSS in Restoring Archived Tasks](https://hackerone.com/reports/177757) to Harvest - 12 upvotes, $250
820. [XSS в названии лайвчата](https://hackerone.com/reports/321419) to Mail.ru - 12 upvotes, $250
821. [Reflected XSS (myynti.lahitapiolarahoitus.fi)](https://hackerone.com/reports/324423) to LocalTapiola - 12 upvotes, $250
822. [store xss in calendar via upload filename](https://hackerone.com/reports/385407) to Open-Xchange - 12 upvotes, $250
823. [dom xss in https://www.slackatwork.com](https://hackerone.com/reports/196624) to Slack - 12 upvotes, $200
824. [Dom based xss affecting all pages from https://www.grab.com/.](https://hackerone.com/reports/247246) to Grab - 12 upvotes, $200
825. [stored xss путём загрузки вредоносного файла + обход загрузки файлов.](https://hackerone.com/reports/888254) to Mail.ru - 12 upvotes, $200
826. [XSS at af.attachmail.ru](https://hackerone.com/reports/85421) to Mail.ru - 12 upvotes, $150
827. [[XSS/pay.qiwi.com] Pay SubDomain Hard-Use XSS](https://hackerone.com/reports/198251) to QIWI - 12 upvotes, $150
828. [Stored XSS in markdown file with Nextcloud Talk using Internet Explorer](https://hackerone.com/reports/1023787) to Nextcloud - 12 upvotes, $150
829. [Follow Button XSS](https://hackerone.com/reports/172574) to Automattic - 12 upvotes, $100
830. [[stage-go.wepay.com] XSS via Request URI](https://hackerone.com/reports/281038) to WePay - 12 upvotes, $100
831. [Stored XSS via AngularJS Injection](https://hackerone.com/reports/141463) to drchrono - 12 upvotes, $50
832. [Stored XSS using  SVG ](https://hackerone.com/reports/148853) to Paragon Initiative Enterprises - 12 upvotes, $50
833. [Stored Cross Site Scripting in Customer Name](https://hackerone.com/reports/211643) to Moneybird - 12 upvotes, $50
834. [Stored XSS at Moneybird](https://hackerone.com/reports/251043) to Moneybird - 12 upvotes, $50
835. [DOM Based XSS on an Army website](https://hackerone.com/reports/191407) to U.S. Dept Of Defense - 12 upvotes, $0
836. [WordPress \<= 4.6.1 Stored XSS Via Theme File](https://hackerone.com/reports/197878) to Nextcloud - 12 upvotes, $0
837. [Stored XSS in Headline TextControl element in Express forms [ concrete5 8.1.0 ]](https://hackerone.com/reports/230278) to Concrete CMS - 12 upvotes, $0
838. [Torrent extension: Cross-origin downloading + "URL spoofing" + CSP-blocked XSS](https://hackerone.com/reports/378864) to Brave Software - 12 upvotes, $0
839. [DOM XSS on 50x.html page on proxy.duckduckgo.com](https://hackerone.com/reports/426275) to DuckDuckGo - 12 upvotes, $0
840. [[rm.mail.ru] Request-Path XSS](https://hackerone.com/reports/386100) to Mail.ru - 12 upvotes, $0
841. [XSS](https://hackerone.com/reports/496841) to Mail.ru - 12 upvotes, $0
842. [Html Injection and Possible XSS via MathML](https://hackerone.com/reports/502926) to Twitter - 12 upvotes, $0
843. [Reflected XSS on www.olx.co.id via ad_type parameter](https://hackerone.com/reports/633751) to OLX - 12 upvotes, $0
844. [Unauthenticated reflected XSS in preview_as_user function](https://hackerone.com/reports/643442) to Concrete CMS - 12 upvotes, $0
845. [Reflected xss on 8x8.vc](https://hackerone.com/reports/771110) to 8x8 - 12 upvotes, $0
846. [[htmr] DOM-based XSS](https://hackerone.com/reports/753971) to Node.js third-party modules - 12 upvotes, $0
847. [XSS in [community.my.games]](https://hackerone.com/reports/848732) to Mail.ru - 12 upvotes, $0
848. [Reflected XSS](https://hackerone.com/reports/874093) to Mail.ru - 12 upvotes, $0
849. [XSS on https://fax.pbx.itsendless.org/ (CVE-2017-18024)](https://hackerone.com/reports/963798) to Endless Group - 12 upvotes, $0
850. [[m-server] XSS reflected because path does not escapeHtml](https://hackerone.com/reports/951468) to Node.js third-party modules - 12 upvotes, $0
851. [Stored XSS at "Conditions "  through "My Custom Rule" Field at [https://my.stripo.email/cabinet/#/template-editor/] in Template Editor.](https://hackerone.com/reports/996371) to Stripo Inc - 12 upvotes, $0
852. [Reflected XSS on /admin/stats.php](https://hackerone.com/reports/1187820) to Revive Adserver - 12 upvotes, $0
853. [Reflected XSS on play.mtn.co.za](https://hackerone.com/reports/1061199) to MTN Group - 12 upvotes, $0
854. [XSS in ubermovement.com via editable Google Sheets](https://hackerone.com/reports/193799) to Uber - 11 upvotes, $2000
855. [Cross-account stored XSS at notes (through "swf" note parameter)](https://hackerone.com/reports/710535) to New Relic - 11 upvotes, $2000
856. [Stored XSS on support.rockstargames.com](https://hackerone.com/reports/265274) to Rockstar Games - 11 upvotes, $1000
857. [XSS в теле письма, в блочных стилях.](https://hackerone.com/reports/277163) to Mail.ru - 11 upvotes, $1000
858. [Unfiltered input allows for XSS in "Playtime Item Grants" fields](https://hackerone.com/reports/353334) to Valve - 11 upvotes, $750
859. [Warehouse dom based xss may lead to Social Club Account Taker Over.](https://hackerone.com/reports/663312) to Rockstar Games - 11 upvotes, $750
860. [XSS в обработчике ссылок](https://hackerone.com/reports/1073571) to VK.com - 11 upvotes, $700
861. [pre-auth Stored XSS in comments via javascript: url when administrator edits user supplied comment](https://hackerone.com/reports/633231) to WordPress - 11 upvotes, $650
862. [[Gnip Blogs] Reflected XSS via "plupload.flash.swf" component vulnerable to SOME ](https://hackerone.com/reports/218451) to Twitter - 11 upvotes, $560
863. [Unsanitized Location Name in POS Channel can lead to XSS in Orders Timeline](https://hackerone.com/reports/166887) to Shopify - 11 upvotes, $500
864. [Xss в https://e.mail.ru/](https://hackerone.com/reports/227181) to Mail.ru - 11 upvotes, $500
865. [dom based xss in http://www.rockstargames.com/GTAOnline/ (Fix bypass)](https://hackerone.com/reports/261571) to Rockstar Games - 11 upvotes, $500
866. [[account.mail.ru] XSS на странице восстановления пароля](https://hackerone.com/reports/360787) to Mail.ru - 11 upvotes, $500
867. [Stored Blind XSS](https://hackerone.com/reports/326918) to Mail.ru - 11 upvotes, $500
868. [Stored XSS in mail app](https://hackerone.com/reports/538323) to Open-Xchange - 11 upvotes, $500
869. [XSS в названии звонка](https://hackerone.com/reports/1056953) to VK.com - 11 upvotes, $500
870. [Reflected XSS on blockchain.info](https://hackerone.com/reports/179426) to Blockchain - 11 upvotes, $400
871. [[sub.wordpress.com] - XSS when adjust block Poll - Confirmation Message -  On submission:Redirect to another webpage - Redirect address:[xss_payload]](https://hackerone.com/reports/1050733) to Automattic - 11 upvotes, $350
872. [XSS Vulnerability at https://www.pornhubpremium.com/premium_signup? URL endpoint ](https://hackerone.com/reports/202548) to Pornhub - 11 upvotes, $250
873. [[web.icq.com] Stored XSS in link when sending message](https://hackerone.com/reports/339237) to Mail.ru - 11 upvotes, $250
874. [[theacademy.upserve.com] Reflected XSS Query-String](https://hackerone.com/reports/389592) to Upserve  - 11 upvotes, $250
875. [Reflected XSS of bbe-child-starter Theme via "value"-GET-parameter](https://hackerone.com/reports/335735) to LocalTapiola - 11 upvotes, $250
876. [Reflected XSS on https://www.starbucks.co.uk/shop/paymentmethod/ (bypass for 227486)](https://hackerone.com/reports/252908) to Starbucks - 11 upvotes, $250
877. [Reflected DOM XSS on www.starbucks.co.uk](https://hackerone.com/reports/396493) to Starbucks - 11 upvotes, $250
878. [Eval-based XSS in Game JS API (mailru.core.js) via cross-origin postMessage()](https://hackerone.com/reports/1071294) to Mail.ru - 11 upvotes, $200
879. [Bypassing SOP with XSS on account.my.games leading to steal CSRF token and user information](https://hackerone.com/reports/1215053) to Mail.ru - 11 upvotes, $200
880. [[scores.ubnt.com] DOM based XSS at form.html](https://hackerone.com/reports/158484) to Ubiquiti Inc. - 11 upvotes, $150
881. [Stored XSS in unifi.ubnt.com](https://hackerone.com/reports/142084) to Ubiquiti Inc. - 11 upvotes, $125
882. [Stored xss](https://hackerone.com/reports/156373) to Algolia - 11 upvotes, $100
883. [Post Based XSS On Upload Via CK Editor [semrush.com]](https://hackerone.com/reports/375352) to Semrush - 11 upvotes, $100
884. [Session ID is accessible via XSS](https://hackerone.com/reports/241194) to Inflection - 11 upvotes, $100
885. [XSS on https://www.delivery-club.ru/sd/test_330933/info/](https://hackerone.com/reports/330974) to Mail.ru - 11 upvotes, $100
886. [DOM XSS on http://talks.lystit.com](https://hackerone.com/reports/1031644) to Lyst - 11 upvotes, $100
887. [stored XSS in olx.pl - ogloszenie TITLE element - moderator acc can be hacked](https://hackerone.com/reports/150668) to OLX - 11 upvotes, $0
888. [Reflected Xss on ](https://hackerone.com/reports/182033) to Pushwoosh - 11 upvotes, $0
889. [Reflected cross-site scripting vulnerability on a DoD website](https://hackerone.com/reports/184042) to U.S. Dept Of Defense - 11 upvotes, $0
890. [[app.mixmax.com] Stored XSS on Adding new enhancement.](https://hackerone.com/reports/237100) to Mixmax - 11 upvotes, $0
891. [Stored self-XSS pubg.mail.ru в нескольких местах](https://hackerone.com/reports/280826) to Mail.ru - 11 upvotes, $0
892. [XSS через подгрузку ссылки.](https://hackerone.com/reports/282602) to Mail.ru - 11 upvotes, $0
893. [Stored XSS in the Custom Logo link (non-Basic plan required)](https://hackerone.com/reports/282209) to Infogram - 11 upvotes, $0
894. [Stored XSS on urbandictionary.com](https://hackerone.com/reports/289085) to Urban Dictionary - 11 upvotes, $0
895. [Disclosure of user email address and Deanonymization [mail.ru] + Blind | Stored XSS pets.mail.ru](https://hackerone.com/reports/334230) to Mail.ru - 11 upvotes, $0
896. [Stored XSS via Create Project (Add new translation project)](https://hackerone.com/reports/610219) to Weblate - 11 upvotes, $0
897. [stored xss in https://www.smule.com](https://hackerone.com/reports/733222) to Smule - 11 upvotes, $0
898. [xss in /users/[id]/set_tier endpoint](https://hackerone.com/reports/782764) to RATELIMITED - 11 upvotes, $0
899. [Stored xss on https://go.mail.ru/](https://hackerone.com/reports/832256) to Mail.ru - 11 upvotes, $0
900. [Reflected XSS on https://apps.topcoder.com/wiki/](https://hackerone.com/reports/866426) to Topcoder - 11 upvotes, $0
901. [[my.games] Stored XSS via untrusted bucket](https://hackerone.com/reports/874107) to Mail.ru - 11 upvotes, $0
902. [Unrestricted File Upload Leads to XSS & Potential RCE](https://hackerone.com/reports/900179) to U.S. Dept Of Defense - 11 upvotes, $0
903. [stored xss via Campaign Name.](https://hackerone.com/reports/923679) to lemlist - 11 upvotes, $0
904. [Stored self XSS at auto.mail.ru using add_review functionality](https://hackerone.com/reports/914286) to Mail.ru - 11 upvotes, $0
905. [xss while uploading a file](https://hackerone.com/reports/915346) to Mail.ru - 11 upvotes, $0
906. [Stored-Xss at connect.topcoder.com/projects/ affected on project chat members](https://hackerone.com/reports/779908) to Topcoder - 11 upvotes, $0
907. [Session Hijack via Self-XSS](https://hackerone.com/reports/962902) to Rocket.Chat - 11 upvotes, $0
908. [DOM-based XSS in d.miwifi.com on IE 11](https://hackerone.com/reports/879984) to Xiaomi - 11 upvotes, $0
909. [Blind Stored XSS on ███████  leads to takeover admin account](https://hackerone.com/reports/1110243) to U.S. Dept Of Defense - 11 upvotes, $0
910. [Cross site scripting  ](https://hackerone.com/reports/1095797) to Informatica - 11 upvotes, $0
911. [Reflected XSS on gamesclub.mtn.com.g](https://hackerone.com/reports/1069528) to MTN Group - 11 upvotes, $0
912. [Reflected XSS at [████████]](https://hackerone.com/reports/1196945) to U.S. Dept Of Defense - 11 upvotes, $0
913. [Improper Sanitization leads to XSS Fire on admin panel](https://hackerone.com/reports/1011888) to Informatica - 11 upvotes, $0
914. [Reflected Xss  https://██████/](https://hackerone.com/reports/759418) to U.S. Dept Of Defense - 11 upvotes, $0
915. [Blind XSS via  Digital Ocean Partner account creation form.](https://hackerone.com/reports/880591) to DigitalOcean - 11 upvotes, $0
916. [Universal Cross-Site Scripting vulnerability](https://hackerone.com/reports/1326264) to Proctorio - 11 upvotes, $0
917. [XSS в письме, в теле письма.](https://hackerone.com/reports/269458) to Mail.ru - 10 upvotes, $2000
918. [[panel.city-mobil.ru/admin/] Blind XSS via partner name (similar to #746505)](https://hackerone.com/reports/864598) to Mail.ru - 10 upvotes, $1000
919. [Stored xss in calendar via call link](https://hackerone.com/reports/1121980) to Mail.ru - 10 upvotes, $1000
920. [Xss в https://e.mail.ru/](https://hackerone.com/reports/228531) to Mail.ru - 10 upvotes, $500
921. [Reflected XSS in https://e.mail.ru/](https://hackerone.com/reports/258317) to Mail.ru - 10 upvotes, $500
922. [Хранимая XSS в функционале добавления аудио в WYSIWYG](https://hackerone.com/reports/274112) to VK.com - 10 upvotes, $500
923. [Отраженная XSS на cloud.mail.ru в URL в функционале создания и редактировании презентации.](https://hackerone.com/reports/258596) to Mail.ru - 10 upvotes, $500
924. [XSS bypass Script execute,Read any file,execute any javascript code--UXSS](https://hackerone.com/reports/243058) to Mail.ru - 10 upvotes, $500
925. [Хранимая XSS ( API )](https://hackerone.com/reports/311063) to Mail.ru - 10 upvotes, $500
926. [Improper handling of Chunked data request in sapi_apache2.c leads to Reflected XSS](https://hackerone.com/reports/409986) to Internet Bug Bounty - 10 upvotes, $500
927. [Dropbox Paper - Markdown XSS](https://hackerone.com/reports/223906) to Dropbox - 10 upvotes, $343
928. [Stored xss via template injection](https://hackerone.com/reports/250837) to WordPress - 10 upvotes, $300
929. [Stored XSS in address on [corporate.city-mobil.ru]](https://hackerone.com/reports/956194) to Mail.ru - 10 upvotes, $300
930. [Reflected XSS in scores.ubnt.com](https://hackerone.com/reports/130889) to Ubiquiti Inc. - 10 upvotes, $275
931. [Reflected XSS in login redirection module](https://hackerone.com/reports/216806) to Pornhub - 10 upvotes, $250
932. [Reflected XSS on bbe_open_htmleditor_popup.php of BBE Theme via "value"-GET-parameter](https://hackerone.com/reports/324442) to LocalTapiola - 10 upvotes, $250
933. [Stored XSS in eaccounting.stage.vismaonline.com](https://hackerone.com/reports/897523) to Visma Public - 10 upvotes, $250
934. [DOM-based XSS on https://zest.co.th/zestlinepay/](https://hackerone.com/reports/784112) to Razer - 10 upvotes, $200
935. [Stored XSS Using Media](https://hackerone.com/reports/275386) to Automattic - 10 upvotes, $150
936. [Simple CSS line-height identifies platform](https://hackerone.com/reports/256647) to Tor - 10 upvotes, $100
937. [CSS injection via link tag whitelisted-domain bypass - https://www.glassdoor.com](https://hackerone.com/reports/1250730) to Glassdoor - 10 upvotes, $100
938. [Multiple XSS in Camptix Event Ticketing Plugin](https://hackerone.com/reports/152958) to Ian Dunn - 10 upvotes, $50
939. [Loadbalancer + URI XSS #3](https://hackerone.com/reports/9703) to Yahoo! - 10 upvotes, $0
940. [XSS @ yaman.olx.ph](https://hackerone.com/reports/150565) to OLX - 10 upvotes, $0
941. [XSS On meta tags in profile page](https://hackerone.com/reports/159984) to GitLab - 10 upvotes, $0
942. [Cross-Site Scripting Stored On Rich Media](https://hackerone.com/reports/142540) to Pushwoosh - 10 upvotes, $0
943. [[uk.informatica.com] XSS on uk.informatica..com](https://hackerone.com/reports/143323) to Informatica - 10 upvotes, $0
944. [Reflected XSS in U2F plugin by shipping the example endpoints](https://hackerone.com/reports/192786) to Nextcloud - 10 upvotes, $0
945. [[kb.informatica.com] DOM based XSS in the bindBreadCrumb function](https://hackerone.com/reports/189834) to Informatica - 10 upvotes, $0
946. [[alpha.informatica.com] Expensive DOMXSS](https://hackerone.com/reports/158749) to Informatica - 10 upvotes, $0
