# État après les lignes CRNG / HWRNG

Observations utilisateur : random: crng init done ; registered with the hwrng core.

Ces lignes viennent du noyau Linux et attestent son exécution. Elles ne suffisent pas à attribuer un éventuel blocage au générateur aléatoire : une dernière ligne affichée peut précéder une autre étape qui ne produit aucun message. Le shell et le montage du système ne sont pas confirmés.

La configuration du noyau fourni active NETCONSOLE, NETPOLL et NET_POLL_CONTROLLER, mais pas IP_PNP. L’initramfs analysé ne configure pas de DHCP ou de service distant avant son shell de secours. L’IP d’Orbis ne doit donc pas être supposée active sous Linux. La connexion de la PS4 par Wi-Fi sous Orbis ne prouve pas que netconsole puisse fonctionner au début du noyau.

Étape immédiate : clavier USB, Entrée, puis /proc/version et ip addr si une invite apparaît. Ne pas redémarrer ce noyau pendant cette vérification.

Profil suivant préparé seulement, non déployé : initcall_debug, loglevel=8, ignore_loglevel, ps4_rescue. Il servira à identifier la dernière fonction d’initialisation commencée si le shell ne répond pas. Aucune correction arbitraire de HWRNG n’est appliquée.
