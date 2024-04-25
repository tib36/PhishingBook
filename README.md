<div align="center">
     <h2>PhishingBook </h2>
     <a href="https://github.com/tib36/PhishingBook"> <img src="https://badgen.net/github/stars/tib36/PhishingBook?icon=github&color=black"></a>
    <a href="https://github.com/tib36/PhishingBook"> <img src="https://badgen.net/github/forks/tib36/PhishingBook?icon=github&color=black"></a>
    <br>
    <br>
    <img src="https://nssctf.wdf.ink//img/WDTJ/202305010317162.png" width="300px">
     <h4>红蓝对抗：钓鱼演练资源汇总&amp;备忘录</h4>
       </div> 

#### 目录
- [Office历史漏洞](#分类Office历史漏洞)
- [钓鱼辅助工具项目](#分类钓鱼辅助工具项目)
- [免杀项目](#分类免杀项目)
- [C2项目](#分类c2项目)
- [红队相关其他项目](#分类红队相关其他项目)
- [杂项堆积](#分类杂项堆积)


#### 关于

本项目收集来自网络（主要是github）的钓鱼相关的资源

简单粗暴，基本上仅提供分类、链接和简介

持续更新中。。

**如果有帮助，建议师傅顺手点个免费的Star**

**注：**

本项目出现的资源均收集自公开网络，本项目作者未提供且不提供任何相关技术

这些资源仅仅是收集而来，未经验证是否可用，也没有逐一经过后门检测，因此学习及使用前需自行验证其可用性和安全性，**本项目仅仅是一个整理汇总网络公开资源的markdown页面，仅用于安全技术研究讨论**，请勿进行任何非授权渗透行为，否则请自行承担责任。

**本项目设立的目的仅仅是作为一个资源备忘录使用，用于工作中涉及的安全建设及人员安全意识培训。为防止技术滥用，项目内不对任何实际技术细节及工具进行存档，仅转发相关原作者发布的互联网公开链接。正因如此，本项目无法保证相关资源的安全性。如果您需要对其中的任何技术进行研究学习，请使用自行搭建的虚拟环境。**

欢迎任何纠错及补充（当然，额。。最好是和本项目相关的= =）

---

#### 分类:Office历史漏洞

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
[**WPS-20230809-RCE POC1**](https://github.com/b2git/WPS-0DAY-20230809)|WPS Office RCE|
[**WPS-20230809-RCE POC2**](https://github.com/ba0gu0/wps-rce)|WPS Office RCE|
[**Outlook RCE**](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability)|CVE-2024-21413 Microsoft Outlook漏洞POC|

---

#### 分类:钓鱼辅助工具项目

| 项目名称 | 项目简介 |
|----------|----------|
[**Swaks**](https://github.com/jetmore/swaks)|邮件伪造工具，集成伪装发信人等功能|
[**MatryoshkaDollTool**](https://github.com/TheKingOfDuck/MatryoshkaDollTool)|C#实现的程序加壳/捆绑工具|
[**BeCyIconGrabber Portable**](https://github.com/JarlPenguin/BeCyIconGrabberPortable)|图标提取工具，可用于辅助进行图标伪装|
[**Restorator**](https://www.bome.com/products/restorator)|资源替换工具，可用于图标伪装，但是似乎是一款需付费的工具|
[**SigThief**](https://github.com/secretsquirrel/SigThief)|数字签名伪装|
[**Bad-Pdf**](https://github.com/deepzec/Bad-Pdf)|通过恶意PDF文件窃取NTLM Hash|
[**Lnk-Trojan**](https://github.com/Yihsiwei/Lnk-Trojan)|Lnk钓鱼工具，来自Yihsiwei师傅（职业红队）|
[**EmailAll**](https://github.com/Taonn/EmailAll)|一款强大的邮箱收集工具 |
[**sendMail**](https://github.com/1n7erface/sendMail)|批量群发钓鱼邮件|
[**ditt**](https://github.com/evilsocket/ditto)|生成高仿域名|
[**PhishingInstall**](https://github.com/sumerzhang/PhishingInstall)|快速搭建钓鱼邮服|
[**社工字典**](https://github.com/zgjx6/SocialEngineeringDictionaryGenerator)|社会工程学密码生成器|
[**EasyPersistent**](https://github.com/yanghaoi/CobaltStrike_CNA)|CobaltStrike的权限维持插件，支持多种权限维持方法|
[**Gophish**](https://github.com/gophish/gophish)|Gophish，一款大型开源钓鱼框架|
[**Flash-Pop**](https://github.com/r00tSe7en/Flash-Pop)|Flash钓鱼弹窗版|
[**Fake-flash.cn**](https://github.com/r00tSe7en/Fake-flash.cn)|旧版Flash钓鱼页，中文+英文，可能需要改改再用|
[**Goblin 钓鱼演练工具**](https://github.com/xiecat/goblin)|适用于红蓝对抗的钓鱼演练工具。通过反向代理，可以在不影响用户操作的情况下无感知的获取用户的信息，或者诱导用户操作。支持隐藏服务端，支持docker快速部署|
[**Medusa**](https://github.com/Ascotbe/Medusa)|Medusa红队作战平台|
[**idea-project-fish-exploit**](https://github.com/no-one-sec/idea-project-fish-exploit)|JetBrains系列产品.idea钓鱼反制红队 |
[**IDE-Honeypot**](https://github.com/wendell1224/ide-honeypot)|一款针对于IDE的反制蜜罐。通过项目文件钓鱼的思路理论上可对部分IDE实现无感触发|
[**CrossNet**](https://github.com/dr0op/CrossNet-Beta)|红队行动中利用白利用、免杀、自动判断网络环境生成钓鱼可执行文件。 |
[**LNKUp**](https://github.com/Plazmaz/LNKUp)|恶意Lnk钓鱼生成器|
[**EBurst**](https://github.com/grayddq/EBurst)|Exchange邮箱爆破|
[**cli.im在线工具**](https://cli.im/tools)|在线生成和编辑二维码|
[**Taie-AutoPhishing**](https://github.com/taielab/Taie-AutoPhishing)|钓鱼工具及思路汇总|

---

#### 分类:免杀项目

| 项目名称 | 项目简介 |
|----------|----------|
[**BypassAntiVirus**](https://github.com/TideSec/BypassAntiVirus)|TideSec的系列免杀教程|
[**掩日**](https://github.com/1y0n/AV_Evasion_Tool)|强大的红队免杀工具，截至目前仍在更新，可用性较强|
[**遮天**](https://github.com/yqcs/ZheTian)|遮天-免杀生成工具|
[**潮影-在线免杀平台**](http://bypass.tidesec.com/)|线上版免杀工具平台|
[**GobypassAV-shellcode**](https://github.com/Pizz33/GobypassAV-shellcode)|CobaltStrike shellcode强效免杀|
[**Bundler-bypass**](https://github.com/testxxxzzz/Bundler-bypass)|免杀捆绑器|
[**GoFileBinder**](https://github.com/Yihsiwei/GoFileBinder)|Golang免杀捆绑器，来自Yihsiwei师傅|
[**CS插件BypassAV**](https://github.com/hack2fun/BypassAV)|Cobalt Strike插件，用于快速生成免杀的可执行文件|
[**PengCode**](https://github.com/Mephostophiles/PengCode)|将exe转换为shellcode|
[**rust-shellcode**](https://github.com/b1nhack/rust-shellcode)|rust实现的shellcode加载器，支持多种加载方式|
[**NimShellCodeLoader**](https://github.com/aeverj/NimShellCodeLoader)|使用小众的Nim语言实现的加载器，主要针对国产杀软|
[**PicBypass**](https://github.com/soryecker/PicBypass)|远程加载shellcode图片来免杀，可以作为思路然后通过其他语言扩展|
[**Amsi-Bypass-Powershell**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)|绕过Windows AMSI|
[**CS-Avoid-killing**](https://github.com/Gality369/CS-Loader)|CobaltStrike免杀加载器|
[**Bypass Anti-Virus**](https://github.com/midisec/BypassAnti-Virus)|一些杀软绕过姿势|
[**bypassAV**](https://github.com/pureqh/bypassAV)|免杀shellcode加载器|
[**GolangBypassAV**](https://github.com/safe6Sec/GolangBypassAV)|Golang下的免杀思路和工具|
[**Malleable C2**](https://github.com/threatexpress/malleable-c2)|用于混淆CobaltStrike流量特征（实战中还需要修改其他特征，例如证书）|
[**CrossC2**](https://github.com/gloxec/CrossC2)|经典项目，用于生成跨平台beacon|
[**NoteRCE**](https://github.com/xiao-zhu-zhu/noterce)|一种另辟蹊径的免杀执行系统命令的木马,防溯源，无需VPS|
[**KaynLdr**](https://github.com/Cracked5pider/KaynLdr)|用C / ASM编写的反射加载器|
[**killEscaper**](https://github.com/Anyyy111/killEscaper)|利用shellcode来制作免杀exe的工具，可结合渗透工具生成的shellcode二次转换exe，支持CobaltStrike、metasploit等|
[**DamnPythonEvasion**](https://github.com/baiyies/DamnPythonEvasion)|基于python pyd的shellcode免杀绕过|

---

#### 分类:C2项目

| 项目名称 | 项目简介 |
|----------|----------|
[**Sliver**](https://github.com/BishopFox/sliver)|Sliver C2框架，貌似最近比较火|
[**RustDesk**](https://github.com/rustdesk/rustdesk)|一款开源、支持普通用户权限、支持纯内网环境的远程桌面控制软件，且不容易被查杀|
[**Covenant**](https://github.com/cobbr/Covenant)|Covenant，一款 .NET C2|
[**Manjusaka**](https://github.com/YDHCUI/manjusaka)|一款基于WEB界面的远程主机管理工具（被国外安全厂商当成APT来分析的那种）|
[**Havoc**](https://github.com/HavocFramework/Havoc)|Havoc，类似CobaltStrike，基本上相当于重写了CS|
[**BlackMamba**](https://github.com/loseys/BlackMamba)|Python编写的开源C2框架|
---

#### 分类:红队相关其他项目

| 项目名称 | 项目简介 |
|----------|----------|
[**APT事件报告汇总-1**](https://apt.360.net/timeline)|国内某公司整理的APT分析报告，部分手法可参考并落地|
[**APT事件报告汇总-2**](https://ti.qianxin.com/apt/)|国内某公司整理的APT分析报告，部分手法可参考并落地|
[**APT事件报告汇总-3**](https://starmap.dbappsecurity.com.cn/apt/map)|国内某公司整理的APT分析报告，部分手法可参考并落地|
[**Fish-Hub**](https://github.com/ybdt/fish-hub)|钓鱼相关案例和参考|
[**红队防猝死手册**](https://github.com/zhutougg/RedteamStandard)|红队防猝死手册，一些防止犯低级错误的指南|
[**红队笔记**](https://github.com/biggerduck/RedTeamNotes)|强大且全面的红队指南|
[**红队知识库**](https://github.com/Threekiii/Awesome-Redteam)|一个红队知识库|

---

#### 分类:杂项堆积

| 杂项 |
|----------|
[**企业钓鱼演练总结**](https://xz.aliyun.com/t/13287)|
[**钓鱼研判经验**](https://xz.aliyun.com/t/13629)|
[**钓鱼指南**](https://xz.aliyun.com/t/7958)|
[**邮件钓鱼平台搭建**](https://xz.aliyun.com/t/11898)|
[**钓鱼具体手法**](https://xz.aliyun.com/t/11885)|
[**钓鱼手法分析**](https://xz.aliyun.com/t/11519)|
[**Office钓鱼姿势**](https://xz.aliyun.com/t/10339)|
[**Windows凭据钓鱼窃取**](https://xz.aliyun.com/t/7458)|
[**邮件钓鱼技巧（提高成功率）**](https://xz.aliyun.com/t/6325)|
[**钓鱼姿势汇总（CHM、自解压等）**](https://www.jianshu.com/p/dcd250593698)|
[**自解压钓鱼详解**](https://www.cnblogs.com/thespace/p/15520945.html)|
[**渗透Exchange邮服**](https://zhuanlan.zhihu.com/p/339329927)|
[**钓鱼优秀战例**](https://xz.aliyun.com/t/10731)|
[**反制红队的钓鱼优秀战例**](https://zhuanlan.zhihu.com/p/656856056)|

---

[![Star History Chart](https://api.star-history.com/svg?repos=tib36/PhishingBook&type=Date)](https://star-history.com/#star-history/star-history&Date)
