BasBase de données
---
🔹 Introduction

Le but de ce projet est d’implémenter un forum. Un forum est un espace de discussion publique, ouvert à plusieurs participants afin de partager des informations et des idées avec d’autres personnes.
Le projet est divisé en trois grandes parties principales : la base de données, le backend en Go, et le frontend.

La base de données constitue le fondement du système du forum. Elle centralise toutes les données essentielles, notamment les informations des utilisateurs, les discussions, les posts, les commentaires, les likes, et éventuellement les sessions qui sont stockées en base. Une bonne structuration des tables garantit la cohérence, la sécurité et la performance du système.

Dans ce projet, plusieurs tables ont été mises en place, avec des noms d’attributs en anglais de préférence afin d’éviter des noms trop francisés.
🔹 Les tables

Comme mentionné ci-dessus, la base de données est conçue autour de plusieurs tables principales :

users : cette table contient les données des utilisateurs avec les colonnes : id, username, email, password_hash, image.
threads : cette table regroupe les discussions créées par les utilisateurs avec les colonnes : id, title, user_id.

Autres tables importantes :

comments : stocke tous les commentaires.
likes : enregistre les likes des posts.
replies : pour les réponses aux discussions.
sessions : stocke les sessions des utilisateurs connectés.
posts : stocke les posts créés.

🔹 Les requêtes SQL utilisées

On a principalement utilisé les commandes : INSERT, SELECT, JOIN, ORDER BY.

INSERT : utilisée pour envoyer les informations du frontend à la base de données via le backend.
SELECT : permet de récupérer les informations depuis la base de données, puis de les envoyer au backend en Go.
JOIN : essentielle pour travailler avec plusieurs tables à la fois ; utilisée pour faire des jointures.
ORDER BY : permet de trier les posts par catégorie.

🔹 Conclusion

La base de données MySQL offre une structure cohérente, optimisée pour la scalabilité du forum. Elle respecte les exigences du projet : authentification, filtres, gestion des messages, visibilité, etc.
----
Le backend Go

🔹 Introduction

Le backend du projet est développé en Go, en tirant parti de sa rapidité, de sa simplicité syntaxique et de sa puissance pour la gestion des serveurs HTTP et de la concurrence. Le backend assure l’interface entre le frontend et la base de données.
Le backend est structuré autour de plusieurs fonctions HTTP Handlers :

1. connexion_DB : 
- Établit une connexion à la base de données MySQL.
- Vérifie la connexion avec db.Ping() et affiche un message en cas de réussite ou d'erreur.
- Cette fonction utilise le driver MySQL pour interagir avec la base de données.

2.	inscription : Inscription avec contrôle de doublon, hashage du mot de passe. Gère l’inscription d’un nouvel utilisateur.
- Traite les requêtes GET et POST (index.html)
- GET affiche le formulaire d'inscription. POST récupère les données du formulaire.
- Gère le téléchargement et la lecture de la photo de profil.
- Crypte le mdp et enregistre les détails de l'utilisateur dans la base de données. 

3.	connexion_utilisateur :
- Authentifie l’utilisateur, crée une session via cookie.
- Gère la connexion des utilisateurs déjà inscrits.
- Traite les requêtes GET et POST (connexion.html)

Processus:
- GET affiche le formulaire de connexion.
- POST récupère l'email et le mot de passe du formulaire. •Vérifie si l'utilisateur existe dans la base de données.
- Compare le mot de passe fourni avec le mot de passe haché.
- Si valide, crée une nouvelle session et envoie un cookie de session au navigateur pour garder le compte connecté (10min)
- Redirige l'utilisateur vers la page d'accueil après une connexion réussie.

4. creer_Une_discussion:
- Crée	une	nouvelle	discussion, accessible uniquement aux utilisateurs connectés.

5. information_forum :
- Affiche les discussions disponibles.

6 envoie_Une_Reponse :
- Ajouter des commentaires à une discussion.
  
7. SessionValide:
- Permet de vérifier si un utilisateur est encore connecté.
 
Ensuite il ya des fonctions completaires comme:

- generationDeSessionID: elle cree une un identifiant unique pour chaque session 
- creationDeSession: cree une une sessions pour chaque utilisateur connecté
- SupprimerLesSessionsExpirer: supprime une session deja expirer
- Deconnexion : permet a un utilisateur connecté de se déconnecter
- supprimerLaSession : supprime dans la base de donnée la session de l’utilisateur deconnecté.
- MOTdePassCrypter : pour crypter les mot de passe recuperer_utilisateur_actuel : recuper l’utilisateur connecté a chaque réquête recuperer_Les_reponses : recuper les reponses de chaque discution recuperer_les_Discussions : elle recupere toutes les discutions
- ajouter_Un_post : ajoute une post en recuperant le contenu du post et image illustrant le post
- recuperer_Les_Posts : depuis la base de donée , elle recupere tous les post deja creer
- recuperer_Les_Posts_Par_category : recupere les posts en les triant par categorie
- affiche_les_categori_de_post : elle recuper la categorie depuis l’url et affiche les posts selon cette catégorie
- recupere_Comentaire_d1_Post: chaque post a ses propres commentaire , cette fonction recuoer les commentaire lier a une fonction
- afficher_les_comentaire_d1_post: elle affiche les commentaires de chaque post
- ajouter_Un_Commentaire : permet d’inserer les commentaires dan la base de données
----
Le frontend

Le frontend fonctionne de manière dynamique tout en intégrant toutes les fonctionnalités du forum.
Cela permet une navigation fluide, avec une interface conviviale et moderne.

Avec toutes ces pages, combinées à un backend solide, nous avons pu obtenir une interface utilisateur simple, fluide et agréable à utiliser.
---

Résumé
Ce projet de forum est une excellente introduction à un ensemble complet de compétences :
✅ Conception de base de données relationnelle (MySQL)
✅ Développement backend sécurisé (Go + sessions)
✅ Création d’un frontend interactif en single-page app
✅ Intégration des sessions et authentification avec cookies
✅ Respect des bonnes pratiques du Web et du projet
