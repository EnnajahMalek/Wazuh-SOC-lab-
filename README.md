# Wazuh-SOC-lab- 
Step 1 
Creation de toplogie: 
  `Mon toplogie jusqu'a ce moment la est  :` un wazuh server, un windows server, une machine utilisateur windows et une machine kali linux  
  `etape 1:` Creation d'un foret Active Directory  `malek.project` , le server est le domain controller 
  `etape 2:` Liee le foret avec un host (dans mon cas la machine utilisateur windows) , d'abord il faut que les machines sont dans le meme reseau, je dois affecter un addresse statique au domain controller et au machine host, une teste de ping est bien on cherche aussi le domain `malek.project` avec un `nslookup malek.project` pour trouver si les 2 machines sont trouvable dans le meme reseau
pour ajouter un utilisateur et un computor, dans le server manager, dans le menu `tools` on click sur `Active Directory Users and Computers` on ajoute un utilisateur dans le domain `Lab User1` avec un logon `labuser@malek.project`, pour connecter la machine avec le domain controller, il faut venir vers le fichier `sysdm.cpl` et modifier le domain du pc, apres le login du Administrateur de domain, et apres redemarrage then login via le login pour le username : `monuser@malek.project` et le password donnee
  
  `etape 3:` installation du log collector sysmon, il faut telecharger le zip du sysmon qui est trouvable dans `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon` et telecharger le fichier xml trouvable dans le github `https://github.com/swiftonsecurity/sysmon-config` unzip les 2 fichiers, et creer un dossier et on ajoute les 2 fichiers, `Sysmon64.exe` et `sysmonconfig-export.xml`, dans le dossier via powershell, la meme chose est faite mais dans la machine client, il faut ouvrir le terminal en mode adminstrateur avec le login d'admin du domain
  `etape 4: ` installaion des agents wazuh , il faut d'abord confirmer l'adresse du reseau prive du server azuh et apres, on peut creer des agents d'apres le GUI Wazuh et il nous donne la commande  comme ca : `Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='192.168.10.11' WAZUH_AGENT_NAME='exemple' WAZUH_REGISTRATION_SERVER='192.168.10.11' ` pour les 2 machines, le controlleur et la machine utilisateur.

Simulations des attacks Mitres 
1- T1087.002 Account Discovery: Domain Account
un type d'attaque mitres ou un utilisateur cherche des utilisateurs qui sonts trouvee dans la domaine avec des requetes LDAP , exemple ou on trouve le journal dans Wazuh:


<img width="1501" height="637" alt="image" src="https://github.com/user-attachments/assets/d5857884-c51f-4f79-8bcd-93357b4b5788" />
c'est quoi une requetes ldap?  ils sont des queries to search for, retrieve, or filter information about users, groups, computers, and other network resources
exemples de requetes LDAP : net groups /domain , net users /domain  net group "groupe specifique" /domain etc ou on peut utiliser des software puissants comme Bloodhound pour faire le recon voici un exemple de net group "domain admin" /domain :


<img width="566" height="214" alt="image" src="https://github.com/user-attachments/assets/60df2207-73ee-42fa-9a37-e8ab145044a6" />
Comment detecter ce type des requests? Sysmon detecte tous les journals de creation des processus Sysmon event ID 1 (process creation) 
la majeur probleme avec ce recon est il n'est pas preventable, car le domain controlleur utilise ces quesries LDAP pour verifieir qu'est ce qu'il est dans le domain , la meilleur option est de detecter le recon au lieu de preventer lui, donc il faut creer une regle wazuh pour detecter ce probleme, les regles wazuh custom sont creer ici  `/var/ossec/etc/rules/local_rules.xml`  wazuh principalement offre ce regle avec un niveau 3 
<img width="1509" height="785" alt="image" src="https://github.com/user-attachments/assets/3d25640d-d701-4229-8842-6ac6f9e284e1" />
et dans l'autre  image on peut voir le rule qui
<img width="656" height="159" alt="image" src="https://github.com/user-attachments/assets/0e29688e-f589-4435-a5dc-754e0ec12e6f" />
<img width="769" height="165" alt="image" src="https://github.com/user-attachments/assets/81a78451-927c-4b04-8511-76b478769f68" />

on trouve
