# PhishingBook
**钓鱼攻击资源汇总&amp;备忘录**

本项目收集来自网络（主要是github）的钓鱼相关的资源
简单粗暴，基本上仅提供分类、链接和简介
持续更新中。。

**如果有帮助，建议师傅顺手点个免费的Star**

**注：**
本项目出现的资源均收集自公开网络，本项目作者未提供且不提供任何相关技术
这些资源仅仅是收集而来，未经验证是否可用，也没有逐一经过后门检测，因此学习及使用前需自行验证其可用性和安全性，**本项目仅仅是一个整理汇总网络公开资源的markdown页面，仅用于安全技术研究讨论**，请勿进行任何非授权渗透行为，否则请自行承担责任。

欢迎任何纠错及补充（当然，额。。最好是和本项目相关的= =）

---

**分类:Office历史漏洞**

| 项目名称 | 项目简介 |
|----------|----------|
[**office-exploits**](https://github.com/SecWiki/office-exploits)|Office-Exploits：Office漏洞集合（包含噩梦公式等历史漏洞，项目较老）|
[**office-exploit-case-study**](https://github.com/houjingyi233/office-exploit-case-study)|Office 历史EXP及学习项目|
[**CVE-2023-21716**](https://github.com/Xnuvers007/CVE-2023-21716)|CVE-2023-21716 POC（Windows 10）|
[**'Follina' MS-MSDT n-day Microsoft Office RCE**](https://github.com/chvancooten/follina.py)|CVE-2022-30190 'Follina' Office RCE 测试工具|
[**'Follina' MS-MSDT n-day Microsoft Office RCE—修改版**](https://github.com/komomon/CVE-2022-30190-follina-Office-MSDT-Fixed)|修改版Follina，支持自定义Word模板。 |
[**CVE-2021-40444**](https://github.com/lockedbyte/CVE-2021-40444)|CVE-2021-40444 POC|
[**CVE-2021-40444**](https://github.com/klezVirus/CVE-2021-40444)|CVE-2021-40444 EXP|
[**MSHTML-RCE-Exploit**](https://github.com/34zY/Microsoft-Office-Word-MSHTML-Remote-Code-Execution-Exploit)|CVE-2021-40444 Demo|
[**CVE-2017-0199**](https://github.com/bhdresh/CVE-2017-0199)|CVE-2017-0199 EXP|
[**PoC Exploit for CVE-2018-0802**](https://github.com/rxwx/CVE-2018-0802)|PoC Exploit for CVE-2018-0802|
[**CVE-2022-24934**](https://github.com/webraybtl/CVE-2022-24934)|WPS Office 历史漏洞Demo|

---

**分类:钓鱼辅助工具项目**

| 项目名称 | 项目简介 |
|----------|----------|
[**EmailAll**](https://github.com/Taonn/EmailAll)|一款强大的邮箱收集工具 |
[**sendMail**](https://github.com/1n7erface/sendMail)|批量发送钓鱼邮箱|
[**Flash-Pop**](https://github.com/r00tSe7en/Flash-Pop)|Flash钓鱼弹窗版|
[**Fake-flash.cn**](https://github.com/r00tSe7en/Fake-flash.cn)|旧版Flash钓鱼页，中文+英文，可能需要改改再用|
[**Goblin 钓鱼演练工具**](https://github.com/xiecat/goblin)|适用于红蓝对抗的钓鱼演练工具。通过反向代理，可以在不影响用户操作的情况下无感知的获取用户的信息，或者诱导用户操作。支持隐藏服务端，支持docker快速部署|
[**Medusa**](https://github.com/Ascotbe/Medusa)|Medusa红队作战平台|
[**idea-project-fish-exploit**](https://github.com/no-one-sec/idea-project-fish-exploit)|JetBrains系列产品.idea钓鱼反制红队 |
[**IDE-Honeypot**](https://github.com/wendell1224/ide-honeypot)|一款针对于IDE的反制蜜罐，通过项目文件等手段钓鱼，理论上可对部分IDE实现无感触发|
[**CrossNet**](https://github.com/dr0op/CrossNet-Beta)|红队行动中利用白利用、免杀、自动判断网络环境生成钓鱼可执行文件。 |
[**LNKUp**](https://github.com/Plazmaz/LNKUp)|恶意Lnk钓鱼生成器|
[**Taie-AutoPhishing**](https://github.com/taielab/Taie-AutoPhishing)|钓鱼工具及思路汇总|

---

**分类:免杀项目**

| 项目名称 | 项目简介 |
|----------|----------|
[**BypassAntiVirus**](https://github.com/TideSec/BypassAntiVirus)|TideSec的系列免杀教程|
[**掩日**](https://github.com/1y0n/AV_Evasion_Tool)|一款强大的红队综合免杀工具|
[**CS-Avoid-killing**](https://github.com/Gality369/CS-Loader)|CobaltStrike免杀加载器|
[**Bypass Anti-Virus**](https://github.com/midisec/BypassAnti-Virus)|一些杀软绕过姿势|
[**遮天**](https://github.com/yqcs/ZheTian)|遮天-免杀生成工具|
[**CrossC2**](https://github.com/gloxec/CrossC2)|经典项目，用于生成跨平台beacon|

---

**分类:C2项目**

| 项目名称 | 项目简介 |
|----------|----------|
[**Sliver**](https://github.com/BishopFox/sliver)|Sliver C2框架，貌似最近比较火|
[**Covenant**](https://github.com/cobbr/Covenant)|Covenant，一款 .NET C2|
[**Manjusaka**](https://github.com/YDHCUI/manjusaka)|一款基于WEB界面的远程主机管理工具（被国外安全厂商当成APT来分析的那种）|
[**Havoc**](https://github.com/HavocFramework/Havoc)|Havoc，类似CobaltStrike，基本上相当于重写了CS|

---

**分类:红队相关其他项目**

| 项目名称 | 项目简介 |
|----------|----------|
[**红队防猝死手册**](https://github.com/zhutougg/RedteamStandard)|红队防猝死手册，一些防止犯低级错误的指南|
[**红队笔记**](https://github.com/biggerduck/RedTeamNotes)|强大且全面的红队指南|
[**红队知识库**](https://github.com/Threekiii/Awesome-Redteam)|一个红队知识库|

---

**分类:杂项堆积**

| 杂项 |
|----------|
[**钓鱼指南**](https://xz.aliyun.com/t/7958)|
[**邮件钓鱼平台搭建**](https://xz.aliyun.com/t/11898)|
[**钓鱼具体手法**](https://xz.aliyun.com/t/11885)|
[**Office钓鱼姿势**](https://xz.aliyun.com/t/10339)|
[**Windows凭据钓鱼窃取**](https://xz.aliyun.com/t/7458)|
[**邮件钓鱼技巧（提高成功率）**](https://xz.aliyun.com/t/6325)|
[**钓鱼姿势汇总（CHM、自解压等）**](https://www.jianshu.com/p/dcd250593698)|
[**自解压钓鱼详解**](https://www.cnblogs.com/thespace/p/15520945.html)|
