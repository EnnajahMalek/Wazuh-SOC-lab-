# Wazuh-SOC-lab- 
Step 1 
Creation de toplogie: 
  `Mon toplogie jusqu'a ce moment la est  :` un wazuh server, un windows server, une machine utilisateur windows et une machine ubuntu 
  `etape 1:` Creation d'un foret Active Directory  `malek.project` , le server est le domain controller 
  `etape 2:` Liee le foret avec un host (dans mon cas la machine utilisateur windows) , d'abord il faut que les machines sont dans le meme reseau, je dois affecter un addresse statique au domain controller et au machine host, une teste de ping est bien on cherche aussi le domain `malek.project` avec un `nslookup malek.project` pour trouver si les 2 machines sont trouvable dans le meme reseau
pour ajouter un utilisateur et un computor, dans le server manager, dans le menu `tools` on click sur `Active Directory Users and Computers` on ajoute un utilisateur dans le domain `Lab User1` avec un logon `labuser@malek.project`, pour connecter la machine avec le domain controller, il faut venir vers le fichier `sysdm.cpl` et modifier le domain du pc, apres le login du Administrateur de domain, et apres redemarrage then login via le login pour le username : `monuser@malek.project` et le password donnee
  
  `etape 3:` installation du log collector sysmon, il faut telecharger le zip du sysmon qui est trouvable dans `https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon` et telecharger le fichier xml trouvable dans le github `https://github.com/swiftonsecurity/sysmon-config` unzip les 2 fichiers, et creer un dossier et on ajoute les 2 fichiers, `Sysmon64.exe` et `sysmonconfig-export.xml`, dans le dossier via powershell, la meme chose est faite mais dans la machine client, il faut ouvrir le terminal en mode adminstrateur avec le login d'admin du domain
