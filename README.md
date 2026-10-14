# Wazuh-SOC-lab- 
Step 1 
Creation de toplogie: 
  `Mon toplogie jusqu'a ce moment la est  :` un wazuh server, un windows server, une machine utilisateur windows et une machine ubuntu 
  `etape 1:` Creation d'un foret Active Directory  `malek.project` , le server est le domain controller 
  `etape 2:` Liee le foret avec un host (dans mon cas la machine utilisateur windows) , d'abord il faut que les machines sont dans le meme reseau, je dois affecter un addresse statique au domain controller et au machine host, une teste de ping est bien on cherche aussi le domain `malek.project` avec un `nslookup malek.project` pour trouver si les 2 machines sont trouvable dans le meme reseau
  
