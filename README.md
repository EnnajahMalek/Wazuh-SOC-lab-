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
## 3 
## Recap

| Technique | ATT&CK | Source | Detecte? | Notes |
|---|---|---|---|---|
| Enum utilisateurs basique | T1087.002 | Sysmon EID1 (92039, defaut) | Oui | Match large, faux positifs possibles (`whoami /user`) |
| BloodHound/PowerView | T1087.002 | Sysmon EID1 (100010/100011) | Ecrit, pas valide live | AMSI a bloque l'execution reelle |
| Groupes, Case A | T1069.002 | DC 4662 (100012) | Oui | SACL doit etre sur AdminSDHolder, pas Domain Admins |
| Groupes, Case B (Kali) | T1069.002 | DC 4662 (100012) | Oui | Invisible sans SACL deliberee |
