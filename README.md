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

n trouve que le rule par defaut (id `92039`, level 3) attrape les commandes basiques comme `net user guest` ou `net user /domain`, car son `field` cherche juste le mot `user` suivi d'un espace (`(?i)user\s`) dans `win.eventdata.commandLine`. Son parent (`if_sid`) est `92031`, qui est le rule general Sysmon pour la creation de processus (event ID 1).
 
Le probleme avec ce rule par defaut: il est trop simple. En testant le regex manuellement contre des commandes BloodHound/PowerView, on trouve que:
- `Get-ADUser -Filter *` match (car "ADUser " contient "user" suivi d'un espace)
- `Get-ADGroup -Filter *` ne match PAS (pas de "user" dans la string)
- Le collecteur reel de BloodHound, `SharpHound.exe`, ne match pas du tout — nom de process different, commandline differente
Donc le rule 92039 couvre seulement une partie de l'enumeration des utilisateurs, et rien de l'enumeration des groupes (qui est en fait la technique #2). Pour combler ce vide, j'ai ecrit 2 regles custom dans `local_rules.xml`, toutes les deux avec le meme parent `92031`:
 
```xml
<rule id="100010" level="7">
  <if_sid>92031</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)sharphound\.exe</field>
  <description>possbilite d'acte de reconnaissance</description>
  <mitre>
    <id>T1087.002</id>
  </mitre>
</rule>
 
<rule id="100011" level="7">
  <if_sid>92031</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)invoke-bloodhound|get-domain(user|group|computer|controller)|get-netgroup|get-netuser</field>
  <description>possibilite d'intrusion via bloodhound ou powerview powershell enumeration : $(win.eventdata.commandLine)</description>
  <mitre>
    <id>T1087.002</id>
  </mitre>
</rule>
```
 
**Note honnete sur la validation:** j'ai essaye de lancer SharpHound et PowerView reellement sur la machine cliente pour confirmer que ces 2 regles s'activent sur du vrai trafic, mais Windows Defender (et plus specifiquement AMSI, qui reste actif meme apres avoir desactive la protection en temps reel) a bloque l'execution des deux outils a chaque fois. Je n'ai donc pas pu valider ces regles contre une execution reelle — seulement contre des logs synthetiques dans `wazuh-logtest`. C'est en soi une observation interessante pour le rapport: AMSI/Defender ont bloque l'attaque avant meme que la detection Wazuh entre en jeu, ce qui montre une couche de defense supplementaire independante de mon pipeline de logging.
 
---
 
2- T1069.002 Permission Groups Discovery: Domain Groups
 
Cette technique est tres proche de la premiere, mais au lieu de chercher les utilisateurs, l'attaquant cherche specifiquement les groupes privileges (Domain Admins, Enterprise Admins) pour identifier les cibles de haute valeur.
 
**Commandes testees** (sur la machine cliente, avec un acces deja etabli — "Case A"):
```
net group /domain
net group "Domain Admins" /domain
Get-ADGroup -Filter *
```
 
**Un deuxieme scenario plus realiste — "Case B":** un attaquant qui n'a PAS de machine compromise dans le domaine, mais qui a acces reseau et un seul identifiant de bas niveau (`labuser`). Depuis Kali (non joint au domaine), j'ai utilise `bloodhound-python` pour faire la meme enumeration via LDAP direct:
 
```bash
bloodhound-python -d malek.project -u labuser -p '********' -ns 192.168.10.10 -c All
```
 
Ce scenario est important car il n'y a aucun Sysmon sur Kali — donc toute la detection basee sur Sysmon (comme technique #1) est completement aveugle ici. La seule chance de detection est cote Domain Controller, via les logs d'audit LDAP natifs.
 
**Investigation de l'audit DC:** par defaut, la sous-categorie d'audit `Directory Service Access` peut etre activee (`auditpol /get /subcategory:"Directory Service Access"`), mais meme activee, elle ne genere AUCUN evenement sans une SACL (System Access Control List) configuree sur l'objet cible. J'ai confirme ca empiriquement — activation de la sous-categorie seule = zero evenements 4662 generes, meme apres plusieurs tests BloodHound.
 
**Probleme rencontre et resolu:** j'ai ajoute une SACL directement sur l'objet `Domain Admins` (Everyone / Success / Read all properties), et ca a fonctionne un temps — mais la SACL disparaissait silencieusement apres environ une heure. La cause: **AdminSDHolder / SDProp**. Domain Admins est un groupe protege dans AD, et un processus en arriere-plan (SDProp) re-applique automatiquement un template de permissions (AdminSDHolder) sur tous les groupes/comptes proteges toutes les heures, effacant au passage toute modification manuelle non presente dans ce template.
 
**Solution:** ajouter la SACL directement sur l'objet `AdminSDHolder` lui-meme (via `adsiedit.msc`, chemin `CN=AdminSDHolder,CN=System,DC=malek,DC=project`), puis forcer la propagation immediatement avec `Invoke-ADSDPropagation` plutot que d'attendre le cycle horaire.
 
**Regle custom ecrite** (`local_rules.xml`), avec comme parent `60103` (le rule generique Wazuh pour "Windows audit success event" sur le channel Security — trouve en tracant la chaine `if_sid` du rule 60106 qui existe deja pour les logons reussis):
 
```xml
<rule id="100012" level="7">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4662$</field>
  <field name="win.eventdata.objectServer">^DS$</field>
  <description>Directory Service object read: $(win.eventdata.subjectUserName) accessed $(win.eventdata.objectType)</description>
  <mitre>
    <id>T1069.002</id>
  </mitre>
</rule>
```
 
**Note sur le champ `accesses`:** ma premiere version du rule incluait aussi une condition sur `win.eventdata.accesses` = "Read Property", basee sur le texte humain-lisible de `Get-WinEvent`. Mais en inspectant le XML brut reel de l'evenement (`.ToXml()`), ce champ n'existe pas sous ce nom — l'information est plutot dans `AccessList` (code `%%7684`, une reference a une table de messages Windows) et `OperationType` (`"Object Access"`). Lecon apprise: toujours verifier la structure XML reelle plutot que de se fier au texte formate par PowerShell.
 
**Validation:** confirme fonctionnel en production — alertes reelles capturees pour `labuser` (via BloodHound, Case B) ET pour `Administrator` (activite legitime du domaine), level 7, correctement tague T1069.002/Discovery.
 
**Limitation honnete a noter:** ce rule detecte TOUTE lecture de l'objet Domain Admins, legitime ou non — il ne distingue pas un administrateur reel d'un attaquant. C'est le meme probleme de faux positifs souleve pour la technique #1: le rule capture le pattern d'acces, pas l'intention.
 
**Tableau recapitulatif pour ces 2 techniques:**
 
| Technique | ATT&CK ID | Source de log | Detecte? | Notes |
|---|---|---|---|---|
| Enumeration utilisateurs (net.exe/PS basique) | T1087.002 | Sysmon EID 1 (rule 92039, par defaut) | Oui | Match large sur "user"; faux positifs possibles (`whoami /user`) |
| Enumeration via BloodHound/PowerView | T1087.002 | Sysmon EID 1 (rules custom 100010/100011) | Regle ecrite, non validee en live | AMSI/Defender ont bloque l'execution reelle des outils dans le lab |
| Enumeration de groupes, Case A (sur machine) | T1069.002 | DC Security log 4662 (rule custom 100012) | Oui | Necessite SACL sur AdminSDHolder, pas sur Domain Admins directement |
| Enumeration de groupes, Case B (Kali, sans machine compromise) | T1069.002 | DC Security log 4662 (rule custom 100012) | Oui, une fois la SACL en place | Invisible sans configuration deliberee — demontre que la detection depend du choix des objets a proteger |
 
