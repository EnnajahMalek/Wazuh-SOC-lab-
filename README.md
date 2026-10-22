# Wazuh SOC Lab

## Topologie
Wazuh server, Windows server (DC), machine utilisateur Windows, machine Kali.

**Etape 1 :** Foret AD `malek.project`, server = domain controller.
**Etape 2 :** Jonction du host Windows au domaine — IP statique sur DC + client, test ping + `nslookup malek.project`. Utilisateur cree dans ADUC (`Lab User1`, `labuser@malek.project`). Jonction au domaine via `sysdm.cpl`, redemarrage, login avec `monuser@malek.project`.
**Etape 3 :** Sysmon installe sur DC et client — binaire + config XML ([SwiftOnSecurity](https://github.com/swiftonsecurity/sysmon-config)).
**Etape 4 :** Agents Wazuh installes sur les 2 machines via le MSI + commande generee par le GUI Wazuh (`WAZUH_MANAGER='192.168.10.11'`).

---

## 1 — T1087.002 Account Discovery: Domain Account

Enumeration des utilisateurs du domaine via requetes LDAP (`net user /domain`, `Get-ADUser`, ou des outils comme BloodHound).

**Detection :** Sysmon event ID 1 (creation de process) — non-preventable car le DC a besoin de ces requetes LDAP pour fonctionner normalement, donc on detecte plutot que bloquer.

Rule par defaut **92039** (level 3, parent `92031`) match `(?i)user\s` dans la commandline — attrape `net user /domain` et `Get-ADUser`, mais rate `Get-ADGroup` et surtout `SharpHound.exe` (nom de process different).

Regles custom ajoutees (`local_rules.xml`) :

```xml
<rule id="100010" level="7">
  <if_sid>92031</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)sharphound\.exe</field>
  <description>possbilite d'acte de reconnaissance</description>
  <mitre><id>T1087.002</id></mitre>
</rule>

<rule id="100011" level="7">
  <if_sid>92031</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)invoke-bloodhound|get-domain(user|group|computer|controller)|get-netgroup|get-netuser</field>
  <description>possibilite d'intrusion via bloodhound ou powerview : $(win.eventdata.commandLine)</description>
  <mitre><id>T1087.002</id></mitre>
</rule>
```

**Non valide en live** — AMSI a bloque SharpHound/PowerView meme Defender desactive. Teste seulement via `wazuh-logtest` synthetique, pas contre du vrai trafic.

---

## 2 — T1069.002 Permission Groups Discovery: Domain Groups

Meme principe que #1 mais cible les groupes privileges (Domain Admins). Teste en 2 cas :
- **Case A** (sur machine, acces deja etabli) : `net group /domain`, `Get-ADGroup -Filter *`
- **Case B** (Kali, non joint au domaine, juste 1 identifiant) :
  ```bash
  bloodhound-python -d malek.project -u labuser -p '***' -ns 192.168.10.10 -c All
  ```

Case B est aveugle a toute detection Sysmon (pas de Sysmon sur Kali) — seul le DC peut detecter, via l'event 4662.

**Probleme rencontre :** `Directory Service Access` auditing active (`auditpol`) ne genere rien sans SACL sur l'objet cible. SACL ajoutee directement sur `Domain Admins` disparaissait apres ~1h.

**Cause :** AdminSDHolder/SDProp re-applique son template de permissions sur les groupes proteges toutes les heures, effacant les modifs manuelles.

**Fix :** SACL ajoutee sur `AdminSDHolder` lui-meme (`adsiedit.msc`), puis `Invoke-ADSDPropagation` pour forcer la propagation immediatement.

Rule finale :
```xml
<rule id="100012" level="7">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4662$</field>
  <field name="win.eventdata.objectServer">^DS$</field>
  <description>Directory Service object read: $(win.eventdata.subjectUserName) accessed $(win.eventdata.objectType)</description>
  <mitre><id>T1069.002</id></mitre>
</rule>
```

(Premiere version verifiait aussi `accesses` = "Read Property" — champ absent du XML reel, retire apres inspection de `.ToXml()`.)

**Confirme en production** — alertes reelles pour `labuser` (BloodHound, Case B) et `Administrator` (activite normale). Limitation : le rule ne distingue pas attaquant vs admin legitime.

---
## 3 — T1110.001 / T1110.003 Brute force / Password spraying (RDP)
 
### Pre-requis : activer le RDP sur la cible
 
Le Bureau a distance est **desactive par defaut** sur Windows 10/11, contrairement a SMB qui ne necessite aucune activation prealable. Sur `CLIENT01` (192.168.10.20) :
 
```powershell
Enable-NetFirewallRule -DisplayGroup "Bureau à distance"   # nom localise FR, pas "Remote Desktop"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Set-NetConnectionProfile -InterfaceIndex <n> -NetworkCategory Private
Add-LocalGroupMember -Group "Utilisateurs du Bureau à distance" -Member "malek\labuser"
```
 
Premier essai avec `-DisplayGroup "Remote Desktop"` (nom anglais) a echoue — Windows FR nomme le groupe de regles pare-feu "Bureau à distance". `Get-NetFirewallRule | Select DisplayGroup -Unique` confirme le nom exact a utiliser. Le profil reseau doit aussi etre en **Private** et non **Public**, sinon les regles de pare-feu RDP restent inactives malgre leur statut "Enabled".
 
Verification avant l'attaque :
```powershell
nmap -p 3389 --reason 192.168.10.20   # depuis Kali : port 3389 open, reason syn-ack
```
 
### Attaque — depuis Kali (192.168.10.50)
 
**T1110.001 — Brute force (1 utilisateur, plusieurs mots de passe) :**
```bash
hydra -l labuser -P passlist.txt rdp://192.168.10.20 -t 1 -W 3
```
*(`-t 1 -W 3` necessaire — le module RDP de Hydra echoue/rate les tentatives avec le parallelisme par defaut, cf. l'avertissement "rdp servers often don't like many connections")*
 
```
[3389][rdp] host: 192.168.10.20   login: labuser   password: pykers123A
1 of 1 target successfully completed, 1 valid password found
```
 
**T1110.003 — Password spraying (plusieurs utilisateurs, 1 mot de passe) :**
```bash
hydra -L userlist.txt -p pykers123A rdp://192.168.10.20 -t 1 -W 3
```
 
### images pour cote bruteforce
<img width="627" height="282" alt="image" src="https://github.com/user-attachments/assets/99169650-3282-4c11-bfe3-f525715f8a26" />
<img width="1481" height="159" alt="image" src="https://github.com/user-attachments/assets/25906ce1-19f0-4a00-94b8-1123fe1a5518" />
 
### images pour cote password spraying
<img width="635" height="289" alt="image" src="https://github.com/user-attachments/assets/181b9f93-cdab-4670-ac02-9c0199921093" />
<img width="1475" height="152" alt="image" src="https://github.com/user-attachments/assets/3ce9b71f-4065-489e-b40f-8b2a36054aaf" />
 
### Detection
 
Pas de regle custom ecrite pour cette section — les echecs et le succes d'authentification RDP sont deja couverts par les regles par defaut de Wazuh sur les evenements Windows standards :
- **Event 4625** (echec de logon, logon type 10/RemoteInteractive) pour chaque mot de passe incorrect essaye par Hydra.
- **Event 4624** (succes de logon, logon type 10) pour la tentative finale reussie (`pykers123A`).
Les deux captures Wazuh ci-dessus confirment que ces evenements remontent correctement depuis `CLIENT01`, aussi bien pour le brute force classique que pour le spraying, sans configuration additionnelle au-dela de l'agent deja en place.
 
**Limitation :** aucun seuil/correlation (ex. "N echecs en X secondes") n'a ete implemente ici — Wazuh affiche les evenements individuels, mais ne les regroupe pas automatiquement en un "incident" de brute force sur un logon Windows comme il le ferait nativement pour SSH. Une regle de correlation par seuil serait l'etape suivante logique pour transformer ce simple logging en vraie detection d'attaque.
 
---
 ### T1558.003 Kerberosting : Vol ou fabrication des certificats Kerberos 
 Kerberos est le methode d'authentification d'AD

 ### 
## Recap
 
| Technique | ATT&CK | Source | Detecte? | Notes |
|---|---|---|---|---|
| Enum utilisateurs basique | T1087.002 | Sysmon EID1 (92039, defaut) | Oui | Match large, faux positifs possibles (`whoami /user`) |
| BloodHound/PowerView | T1087.002 | Sysmon EID1 (100010/100011) | Ecrit, pas valide live | AMSI a bloque l'execution reelle |
| Groupes, Case A | T1069.002 | DC 4662 (100012) | Oui | SACL doit etre sur AdminSDHolder, pas Domain Admins |
| Groupes, Case B (Kali) | T1069.002 | DC 4662 (100012) | Oui | Invisible sans SACL deliberee |
| Brute force RDP | T1110.001 | Client 4625/4624 (defaut) | Oui | RDP desactive par defaut, a activer manuellement |
| Password spraying RDP | T1110.003 | Client 4625/4624 (defaut) | Oui | Pas de seuil/correlation — logging brut, pas d'alerte groupee |
 
