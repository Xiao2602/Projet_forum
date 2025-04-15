package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

var tmpl *template.Template

func connexion_BD() {

	var err error
	dsn := "root:Honoreparis2023@@tcp(127.0.0.1:3306)/forum_db?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Erreur de connexion :", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Impossible de joindre MySQL :", err)
	}
	fmt.Println("Connexion à la base de données réussie.")
	if err != nil {
		log.Fatal("Erreur lors de l'initialisation du store de session :", err)
	}
}

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

func MOTdePassCrypter(password string) (string, error) { //fonction pour crypter le mot de passe
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func inscription(w http.ResponseWriter, r *http.Request) { //fonction pour inscrit

	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "templates/index.html")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")

	username := r.FormValue("username")
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Lire l'image envoyée par l'utilisateur
	file, _, err := r.FormFile("image")
	if err != nil {
		http.Error(w, "Erreur lors du téléchargement", http.StatusInternalServerError)
		fmt.Println("Erreur lors du téléchargement:", err)
		return
	}
	defer file.Close()

	// Lire le fichier en binaire
	avatarData, err := ioutil.ReadAll(file)
	if err != nil {
		http.Error(w, "Erreur de lecture du fichier", http.StatusInternalServerError)
		fmt.Println("Erreur de lecture du fichier:", err)
		return
	}

	hashedPassword, err := MOTdePassCrypter(password)
	if err != nil {
		http.Error(w, "Erreur lors du hash du mot de passe", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO users (username, email, password_hash,image) VALUES (?, ?, ?, ?)",
		username, email, hashedPassword, avatarData)

	if err != nil {
		http.Error(w, "Erreur lors de l'inscription", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Utilisateur %s inscrit avec succès", username)
}

// Gérer connexion + upload d'avatar
type Session struct {
	ID        string
	UserID    int
	ExpiresAt time.Time
}

// Générer un ID de session unique
func generationDeSessionID() string {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

// Créer une session et la stocker en base de données
func creationDeSession(userID int) string {
	// Supprimer toute session existante pour cet utilisateur
	_, err := db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		fmt.Println("❌ Erreur lors de la suppression de l'ancienne session:", err)
	}

	// Créer une nouvelle session
	sessionID := generationDeSessionID()
	expiresAt := time.Now().Add(10 * time.Minute)

	_, err = db.Exec("INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID, userID, expiresAt)
	if err != nil {
		fmt.Println("❌ Erreur lors de la création de la session:", err)
	}
	fmt.Println("🟢 Session créer avec succès:")
	return sessionID
}

// Vérifier si une session est valide
func SessionValide(sessionID string) (Session, bool) {
	var session Session
	err := db.QueryRow("SELECT session_id, user_id, expires_at FROM sessions WHERE session_id = ? AND expires_at > NOW()", sessionID).Scan(&session.ID, &session.UserID, &session.ExpiresAt)
	if err != nil {
		return Session{}, false
	}
	return session, true
}

// Supprimer une session (déconnexion)
func supprimerLaSession(sessionID string) {
	_, err := db.Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
	if err == nil {
		fmt.Println("🔴 Session supprimée de la DB:", sessionID)
	}
}

// Gérer connexion + upload d'avatar
// Gérer connexion + upload d'avatar
func connexion_utilisateur(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "templates/connexion.html")
		return
	}

	// Récupérer email et mot de passe
	email := r.FormValue("email")
	password := r.FormValue("password")

	var userID int
	var hashedPassword string
	var username string

	// Vérifier si l'utilisateur existe
	err := db.QueryRow("SELECT id, username, password_hash FROM users WHERE email = ?", email).Scan(&userID, &username, &hashedPassword)
	if err != nil {
		fmt.Println("⚠️ Erreur SQL ou utilisateur introuvable:", err)
		http.Error(w, "Email ou mot de passe incorrect.", http.StatusUnauthorized)
		return
	}

	// Vérifier le mot de passe
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		fmt.Println("⚠️ Mot de passe incorrect:", err)
		http.Error(w, "Email ou mot de passe incorrect.", http.StatusUnauthorized)
		return
	}

	// Stocker en session
	sessionID := creationDeSession(userID)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
	})
	fmt.Println("🟢 Cookie de session envoyé au naviguateur")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Déconnecte l'utilisateur avec la session la plus récente et connecte le suivant
func Deconnexion(w http.ResponseWriter, r *http.Request) {
	// Récupérer la session la plus récente
	var sessionID string
	err := db.QueryRow("SELECT session_id FROM sessions ORDER BY expires_at DESC LIMIT 1").Scan(&sessionID)
	if err != nil {
		fmt.Println("✅ Plus aucune session active.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Supprimer cette session
	supprimerLaSession(sessionID)
	fmt.Println("🔴 Session supprimée :")

	// Vérifier si le cookie du client correspond à la session supprimée
	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value == sessionID {
		newCookie := &http.Cookie{
			Name:     "session_id",
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			HttpOnly: true,
		}
		http.SetCookie(w, newCookie)
		fmt.Println("🔴 Cookie supprimé pour l'utilisateur déconnecté.")
	}

	// Récupérer la nouvelle session la plus récente après suppression
	var newSessionID string
	var newUserID int
	err = db.QueryRow("SELECT session_id, user_id FROM sessions ORDER BY expires_at DESC LIMIT 1").Scan(&newSessionID, &newUserID)
	if err != nil {
		fmt.Println("✅ Plus aucune session restante, redirection vers page de connexion.")
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Attribuer la session récupérée à l'utilisateur en mettant à jour le cookie
	newCookie := &http.Cookie{
		Name:     "session_id",
		Value:    newSessionID,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
	}
	http.SetCookie(w, newCookie)
	fmt.Println("🟢 Nouvelle session active pour l'utilisateur ID :", newUserID)

	// Rediriger vers homeHandler pour afficher l'utilisateur reconnecté
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func SupprimerLesSessionsExpirer() {
	// Récupérer les sessions expirées
	rows, err := db.Query("SELECT session_id FROM sessions WHERE expires_at <= NOW()")
	if err != nil {
		fmt.Println("❌ Erreur lors de la récupération des sessions expirées:", err)
		return
	}
	defer rows.Close()

	var expiredSessions []string
	for rows.Next() {
		var sessionID string
		if err := rows.Scan(&sessionID); err == nil {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	// Supprimer les sessions expirées
	if len(expiredSessions) > 0 {
		for _, sessionID := range expiredSessions {
			supprimerLaSession(sessionID)
			fmt.Println("🔴 Session expirée supprimée :", sessionID)
		}
	}
}

func recuperer_utilisateur_actuel(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return "", err
	}

	var username string
	err = db.QueryRow(`
		SELECT users.username
		FROM sessions
		JOIN users ON sessions.user_id = users.id
		WHERE sessions.session_id = ? AND sessions.expires_at > ?
	`, cookie.Value, time.Now()).Scan(&username)

	if err != nil {
		return "", err
	}

	return username, nil
}

type Thread struct {
	ID     int
	Title  string
	UserID int
}

// Créer un thread
func creer_Une_discussion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.ServeFile(w, r, "templates/erreur.html")
		return
	}

	session, valid := SessionValide(cookie.Value)
	if !valid {
		http.Error(w, "Session invalide ou expirée", http.StatusUnauthorized)
		return
	}

	title := r.FormValue("title")
	if title == "" {
		http.Error(w, "Le titre ne peut pas être vide", http.StatusBadRequest)
		return
	}

	result, err := db.Exec("INSERT INTO threads (title, user_id) VALUES (?, ?)", title, session.UserID)
	if err != nil {
		http.Error(w, "Erreur lors de la création du thread", http.StatusInternalServerError)
		return
	}
	threadID, err := result.LastInsertId()
	if err != nil {
		http.Error(w, "Erreur lors de la récupération de l'ID", http.StatusInternalServerError)
		return
	}

	// Rediriger vers la page du thread nouvellement créé
	http.Redirect(w, r, "/create_thread="+fmt.Sprint(threadID), http.StatusSeeOther)
}

func information_forum(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT threads.id, threads.title, users.username, users.image 
		FROM threads 
		JOIN users ON threads.user_id = users.id`)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des discussions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var threads []struct {
		ID          int
		Title       string
		Username    string
		Image       []byte // image en binaire
		ImageBase64 string // pour la version encodée
	}

	for rows.Next() {
		var t struct {
			ID          int
			Title       string
			Username    string
			Image       []byte
			ImageBase64 string
		}
		if err := rows.Scan(&t.ID, &t.Title, &t.Username, &t.Image); err != nil {
			http.Error(w, "Erreur lors du scan des discussions", http.StatusInternalServerError)
			return
		}

		if len(t.Image) > 0 {
			contentType := http.DetectContentType(t.Image)
			t.ImageBase64 = "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(t.Image)
		}

		threads = append(threads, t)
	}

	tmpl.ExecuteTemplate(w, "affichage_discussion.html", map[string]interface{}{
		"Threads": threads,
	})
}

func recuperer_Les_reponses(w http.ResponseWriter, r *http.Request) {
	threadID := r.URL.Query().Get("id")
	if threadID == "" {
		http.Error(w, "Thread introuvable", http.StatusBadRequest)
		return
	}

	// Récupérer les infos du thread
	var thread struct {
		ID        int
		Title     string
		User      string
		CreatedAt string
	}

	err := db.QueryRow("SELECT threads.id, threads.title, users.username, threads.created_at FROM threads JOIN users ON threads.user_id = users.id WHERE threads.id = ?", threadID).
		Scan(&thread.ID, &thread.Title, &thread.User, &thread.CreatedAt)

	if err != nil {
		http.Error(w, "Discussion non trouvée", http.StatusNotFound)
		return
	}

	// Récupérer les réponses
	rows, err := db.Query("SELECT replies.content, users.username, replies.created_at FROM replies JOIN users ON replies.user_id = users.id WHERE replies.thread_id = ? ORDER BY replies.created_at ASC", threadID)
	if err != nil {
		http.Error(w, "Erreur lors du chargement des réponses", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var replies []map[string]interface{}
	for rows.Next() {
		var content, username, createdAt string
		if err := rows.Scan(&content, &username, &createdAt); err != nil {
			continue
		}
		replies = append(replies, map[string]interface{}{
			"Content":   content,
			"User":      username,
			"CreatedAt": createdAt,
		})
	}

	tmpl.ExecuteTemplate(w, "envoi_reponse.html", map[string]interface{}{
		"Thread":  thread,
		"Replies": replies,
	})
}

// Répondre à un thread
func envoie_Une_Reponse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Utilisateur non connecté", http.StatusUnauthorized)
		return
	}

	session, valid := SessionValide(cookie.Value)
	if !valid {
		http.Error(w, "Session invalide ou expirée", http.StatusUnauthorized)
		return
	}

	threadID := r.FormValue("thread_id")
	content := r.FormValue("content")

	if threadID == "" || content == "" {
		http.Error(w, "Données incomplètes", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO replies (thread_id, user_id, content) VALUES (?, ?, ?)", threadID, session.UserID, content)
	if err != nil {
		http.Error(w, "Erreur lors de l'ajout de la réponse", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/thread?id="+threadID, http.StatusSeeOther)
}

func recuperer_les_Discussions(w http.ResponseWriter, r *http.Request) {
	threadID := r.URL.Query().Get("id")
	if threadID == "" {
		http.Error(w, "ID manquant", http.StatusBadRequest)
		return
	}
	currentUser, erreur := recuperer_utilisateur_actuel(r)
	if erreur != nil {
		http.Error(w, "Utilisateur non connecté", http.StatusUnauthorized)
		return
	}

	var thread struct {
		ID        int
		Title     string
		User      string
		CreatedAt string
	}

	err := db.QueryRow("SELECT threads.id, threads.title, users.username, threads.created_at FROM threads JOIN users ON threads.user_id = users.id WHERE threads.id = ?", threadID).
		Scan(&thread.ID, &thread.Title, &thread.User, &thread.CreatedAt)
	if err != nil {
		http.Error(w, "Discussion non trouvée", http.StatusNotFound)
		return
	}

	rows, err := db.Query("SELECT replies.content, users.username, replies.created_at FROM replies JOIN users ON replies.user_id = users.id WHERE replies.thread_id = ?", threadID)
	if err != nil {
		http.Error(w, "Erreur lors du chargement des réponses", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var replies []map[string]interface{}
	for rows.Next() {
		var content, username, createdAt string
		if err := rows.Scan(&content, &username, &createdAt); err != nil {
			continue
		}
		replies = append(replies, map[string]interface{}{
			"Content":   content,
			"User":      username,
			"CreatedAt": createdAt,
		})
	}

	tmpl.ExecuteTemplate(w, "thread_partial.html", map[string]interface{}{
		"Thread":      thread,
		"Replies":     replies,
		"CurrentUser": currentUser,
	})

}

// Page principale : afficher l'utilisateur connecté ou page de connexion
func accueil(w http.ResponseWriter, r *http.Request) {
	posts, err := recuperer_Les_Posts() // ✅ Récupération des posts
	if err != nil {
		fmt.Println("⚠️ Erreur lors de la récupération des posts :", err)
		posts = []Post{} // Assure qu'on ne renvoie pas `nil` à la vue
	}

	cookie, err := r.Cookie("session_id")
	if err == nil {
		session, valid := SessionValide(cookie.Value)
		if valid {
			var username string
			var avatarData []byte
			err := db.QueryRow("SELECT username, image FROM users WHERE id = ?", session.UserID).Scan(&username, &avatarData)
			if err == nil {
				var avatarBase64 string
				if len(avatarData) == 0 {
					avatarBase64 = "/static/default-avatar.png"
				} else {
					contentType := http.DetectContentType(avatarData)
					avatarBase64 = "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(avatarData)
				}

				tmpl.ExecuteTemplate(w, "page_principale.html", map[string]interface{}{
					"Message": "Bienvenue, " + username + " !",
					"Nom":     username,
					"Avatar":  avatarBase64,
					"Posts":   posts, // ✅ Ajout des posts
				})
				return
			}
		}
	}

	// Si pas de session, juste afficher les posts
	tmpl.ExecuteTemplate(w, "page_principale.html", map[string]interface{}{
		"Posts": posts, // ✅ Affichage des posts même si pas connecté
	})
}

// Ajouter un post avec une image facultative
func ajouter_Un_post(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Vérifier si l'utilisateur est connecté
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.ServeFile(w, r, "templates/erreur_commentaire.html")
			return
		}

		session, valid := SessionValide(cookie.Value)
		if !valid {
			http.Error(w, "Session invalide, reconnectez-vous.", http.StatusUnauthorized)
			return
		}

		// Récupérer le nom de l'utilisateur
		var username string
		err = db.QueryRow("SELECT username FROM users WHERE id = ?", session.UserID).Scan(&username)
		if err != nil {
			http.Error(w, "Erreur lors de la récupération de l'utilisateur.", http.StatusInternalServerError)
			return
		}

		// Afficher le formulaire avec le nom de l'utilisateur
		tmpl.ExecuteTemplate(w, "creer_post.html", map[string]interface{}{
			"Nom": username,
		})
		return
	}

	// Vérifier si l'utilisateur est connecté
	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "Vous devez être connecté pour publier un post.", http.StatusUnauthorized)
		return
	}

	session, valid := SessionValide(cookie.Value)
	if !valid {
		http.Error(w, "Session invalide, reconnectez-vous.", http.StatusUnauthorized)
		return
	}

	// Récupérer les données du formulaire
	content := r.FormValue("content")
	category := r.FormValue("category")
	title := r.FormValue("title")

	if content == "" {
		http.Error(w, "Le contenu du post ne peut pas être vide.", http.StatusBadRequest)
		return
	}

	// Récupérer le fichier image (s'il y en a un)
	var imageData []byte
	file, _, err := r.FormFile("image")
	if err == nil {
		defer file.Close()
		imageData, err = ioutil.ReadAll(file)
		if err != nil {
			http.Error(w, "Erreur lors de la lecture du fichier.", http.StatusInternalServerError)
			return
		}
	}

	// Insérer dans la base de données
	if len(imageData) > 0 {
		_, err = db.Exec("INSERT INTO posts (user_id, content, category, image, title) VALUES (?, ?, ?, ?, ?)",
			session.UserID, content, category, imageData, title)
	} else {
		_, err = db.Exec("INSERT INTO posts (user_id, content, category, title) VALUES (?, ?, ?, ?)",
			session.UserID, content, category, title)
	}

	if err != nil {
		fmt.Println("⚠️ Erreur lors de l'ajout du post:", err)
		http.Error(w, "Erreur lors de l'ajout du post.", http.StatusInternalServerError)
		return
	}

	fmt.Println("🟢 Post ajouté par l'utilisateur ID:", session.UserID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Récupérer les posts depuis la base de données
func recuperer_Les_Posts() ([]Post, error) {
	rows, err := db.Query(`
		SELECT posts.id, posts.user_id, users.username, users.image, posts.content, posts.category, posts.created_at, 
		       (SELECT COUNT(*) FROM likes WHERE post_id = posts.id AND type = 'like') AS likes, 
		       (SELECT COUNT(*) FROM likes WHERE post_id = posts.id AND type = 'dislike') AS dislikes,
		       posts.image, posts.title
		FROM posts
		JOIN users ON posts.user_id = users.id
		ORDER BY posts.created_at DESC`)

	if err != nil {
		fmt.Println("⚠️ Erreur lors de la récupération des posts:", err)
		return nil, err
	}
	defer rows.Close()

	var posts []Post

	for rows.Next() {
		var post Post
		var createdAt sql.NullTime
		var category sql.NullString
		var title sql.NullString
		var imageData, imageUser []byte
		var username sql.NullString
		var content sql.NullString

		err := rows.Scan(&post.ID, &post.UserID, &username, &imageUser, &content, &category, &createdAt, &post.Likes, &post.Dislikes, &imageData, &title)
		if err != nil {
			fmt.Println("⚠️ Erreur lors de la lecture des données:", err)
			continue
		}

		post.Username = username.String
		post.Content = content.String
		post.Category = category.String
		post.Title = title.String
		if createdAt.Valid {
			post.CreatedAt = createdAt.Time.Format("02/01/2006 15:04")
		}

		if len(imageUser) > 0 {
			contentType := http.DetectContentType(imageUser)
			post.ImageUsers = "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(imageUser)
			//fmt.Println("image recuperer avec succes ")
		}

		if len(imageData) > 0 {
			contentType := http.DetectContentType(imageData)
			post.Image = "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(imageData)
		}

		comments, err := recupere_Comentaire_d1_Post(post.ID)
		if err != nil {
			fmt.Println("⚠️ Erreur lors de la récupération des commentaires du post", post.ID, ":", err)
		}
		post.Comments = comments

		posts = append(posts, post)
	}

	fmt.Println("📌 Nombre de posts récupérés:", len(posts))
	return posts, nil
}

type Post struct {
	ID         int
	UserID     int
	Username   string
	Content    string
	Category   string
	CreatedAt  string
	Likes      int
	Dislikes   int
	Image      string
	ImageUsers string
	Title      string
	Comments   []Comment
}
type Comment struct {
	ID        int
	PostID    int
	UserID    int
	Username  string
	Content   string
	CreatedAt string
}

// Fonction pour récupérer les posts par catégorie depuis la base de données
func recuperer_Les_Posts_Par_category(category string) ([]Post, error) {
	var posts []Post

	// Exécuter la requête SQL pour récupérer les posts par catégorie avec les informations de l'utilisateur
	rows, err := db.Query(`
        SELECT posts.id, posts.title, posts.content, posts.image, posts.category, posts.created_at, users.username,
               (SELECT COUNT(*) FROM likes WHERE post_id = posts.id AND type = 'like') AS likes,
               (SELECT COUNT(*) FROM likes WHERE post_id = posts.id AND type = 'dislike') AS dislikes
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        WHERE posts.category = ? 
        ORDER BY posts.created_at DESC`, category)

	if err != nil {
		fmt.Println("❌ Erreur lors de la récupération des posts:", err)
		return nil, err
	}
	defer rows.Close()

	// Boucle à travers les résultats de la requête
	for rows.Next() {
		var post Post
		var title, content, cat, username sql.NullString
		var createdAt sql.NullTime
		var imageData []byte // Stocke l'image en BLOB

		// Scanner les résultats de chaque ligne en tenant compte des valeurs NULL
		err := rows.Scan(&post.ID, &title, &content, &imageData, &cat, &createdAt, &username, &post.Likes, &post.Dislikes)
		if err != nil {
			fmt.Println("❌ Erreur lors du Scan des posts:", err)
			return nil, err
		}

		// Assurer la gestion des valeurs NULL en les convertissant en chaîne vide si nécessaire
		post.Title = title.String
		post.Content = content.String
		post.Category = cat.String
		post.Username = username.String

		// Gestion du champ `created_at`
		if createdAt.Valid {
			post.CreatedAt = createdAt.Time.Format("02/01/2006 15:04") // Format lisible
		} else {
			post.CreatedAt = "Date inconnue" // Valeur par défaut
		}

		// Conversion de l'image en Base64 si elle existe
		if len(imageData) > 0 {
			contentType := http.DetectContentType(imageData)
			post.Image = "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(imageData)
		} else {
			post.Image = "" // Aucune image
		}

		// Charger les commentaires
		post.Comments, _ = recupere_Comentaire_d1_Post(post.ID)

		posts = append(posts, post)
	}

	// Vérification d'erreurs lors de l'itération des résultats
	if err := rows.Err(); err != nil {
		fmt.Println("⚠️ Erreur lors de l'itération sur les résultats:", err)
		return nil, err
	}

	return posts, nil
}

func recupere_Comentaire_d1_Post(postID int) ([]Comment, error) {
	var comments []Comment

	rows, err := db.Query(`
        SELECT comments.id, comments.post_id, comments.user_id, users.username, comments.content, comments.created_at
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.post_id = ? ORDER BY comments.created_at ASC`, postID)

	if err != nil {
		fmt.Println("❌ Erreur lors de la récupération des commentaires:", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var comment Comment
		var createdAt sql.NullTime
		err := rows.Scan(&comment.ID, &comment.PostID, &comment.UserID, &comment.Username, &comment.Content, &createdAt)
		if err != nil {
			fmt.Println("❌ Erreur lors du scan des commentaires:", err)
			return nil, err
		}
		comment.CreatedAt = createdAt.Time.Format("02/01/2006 15:04")
		comments = append(comments, comment)
	}

	return comments, nil
}

// Handler pour afficher les commentaires d'un post
func afficher_les_comentaire_d1_post(w http.ResponseWriter, r *http.Request) {
	postIDStr := r.URL.Query().Get("post_id")
	postID, err := strconv.Atoi(postIDStr)
	if err != nil {
		http.Error(w, "ID du post invalide", http.StatusBadRequest)
		return
	}

	comments, err := recupere_Comentaire_d1_Post(postID)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des commentaires", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseFiles("templates/comments.html")
	if err != nil {
		http.Error(w, "Erreur de chargement du template", http.StatusInternalServerError)
		return
	}

	data := struct {
		Comments []Comment
		PostID   int
	}{
		Comments: comments,
		PostID:   postID,
	}

	tmpl.Execute(w, data)
}

func Like(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.ServeFile(w, r, "templates/erreur_commentaire.html")
		return
	}

	session, valid := SessionValide(cookie.Value)
	if !valid {
		http.Error(w, "Session invalide, reconnectez-vous.", http.StatusUnauthorized)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil || postID == 0 {
		fmt.Println("❌ post_id est vide ou invalide !")
		http.Error(w, "Post invalide", http.StatusBadRequest)
		return
	}
	fmt.Println("📌 post_id reçu:", postID)

	if err != nil || postID == 0 {
		fmt.Println("❌ Erreur de conversion post_id:", err)
		http.Error(w, "Post invalide", http.StatusBadRequest)
		return
	}

	likeType := r.FormValue("type") // "like" ou "dislike"
	if likeType != "like" && likeType != "dislike" {
		http.Error(w, "Type invalide", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(`
        INSERT INTO likes (user_id, post_id, type)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE type = VALUES(type)`, session.UserID, postID, likeType)

	if err != nil {
		fmt.Println("❌ Erreur SQL lors du like/dislike:", err)
		http.Error(w, "Erreur lors de l'ajout du like/dislike", http.StatusInternalServerError)
		return
	}

	fmt.Println("🟢 Like/dislike mis à jour pour le post:", postID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func ajouter_Un_Commentaire(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.ServeFile(w, r, "templates/erreur_commentaire.html")
		return
	}

	session, valid := SessionValide(cookie.Value)
	if !valid {
		http.Error(w, "Session invalide, reconnectez-vous.", http.StatusUnauthorized)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil || postID == 0 {
		fmt.Println("❌ post_id est vide ou invalide !")
		http.Error(w, "Post invalide", http.StatusBadRequest)
		return
	}
	fmt.Println("📌 post_id reçu:", postID)

	if err != nil || postID == 0 {
		fmt.Println("❌ Erreur de conversion post_id:", err)
		http.Error(w, "Post invalide", http.StatusBadRequest)
		return
	}

	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Le commentaire ne peut pas être vide.", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("INSERT INTO comments (user_id, post_id, content) VALUES (?, ?, ?)", session.UserID, postID, content)
	if err != nil {
		fmt.Println("❌ Erreur SQL lors de l'ajout du commentaire:", err)
		http.Error(w, "Erreur lors de l'ajout du commentaire", http.StatusInternalServerError)
		return
	}

	fmt.Println("🟢 Commentaire ajouté sur le post:", postID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Gestionnaire pour afficher les posts filtrés par catégorie
func affiche_les_categori_de_post(w http.ResponseWriter, r *http.Request) {
	// Récupérer la catégorie depuis la requête
	category := r.URL.Query().Get("category")

	// Appeler la fonction getPostsByCategory pour récupérer les posts
	posts, err := recuperer_Les_Posts_Par_category(category)
	if err != nil {
		http.Error(w, "Erreur lors de la récupération des posts", http.StatusInternalServerError)
		return
	}

	// Vérifier si des posts ont été récupérés
	if len(posts) == 0 {
		tmpl.ExecuteTemplate(w, "category.html", map[string]string{
			"Message": "Aucun post pour cette catégorie.",
		})
		return
	}

	// Passer les posts au template pour affichage
	tmpl.ExecuteTemplate(w, "category.html", map[string]interface{}{
		"Category": category,
		"Posts":    posts,
	})
}

func main() {

	connexion_BD()
	SupprimerLesSessionsExpirer() // Supprime les sessions expirées immédiatement au démarrage

	// Exécuter la suppression des sessions expirées toutes les 1 seconde
	go func() {
		ticker := time.NewTicker(1 * time.Second) // Exécute toutes les 1 seconde
		defer ticker.Stop()

		for range ticker.C {
			SupprimerLesSessionsExpirer()
		}
	}()
	defer db.Close()
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	tmpl = template.Must(template.ParseGlob("templates/*.html"))
	http.HandleFunc("/", accueil)
	http.HandleFunc("/login", connexion_utilisateur)
	http.HandleFunc("/add-post", ajouter_Un_post) // ✅ Route pour ajouter un post avec image
	http.HandleFunc("/register", inscription)
	http.HandleFunc("/forum", information_forum)            // Page principale du forum avec la liste des discussions
	http.HandleFunc("/thread", recuperer_Les_reponses)      // Page d'une discussion spécifique
	http.HandleFunc("/create_thread", creer_Une_discussion) // Création d'un nouveau thread
	http.HandleFunc("/reply", envoie_Une_Reponse)           // Répondre à un thread
	http.HandleFunc("/logout", Deconnexion)
	http.HandleFunc("/posts", affiche_les_categori_de_post)
	http.HandleFunc("/like", Like)
	http.HandleFunc("/comment", ajouter_Un_Commentaire)
	http.HandleFunc("/comments", afficher_les_comentaire_d1_post)
	http.HandleFunc("/get_thread", recuperer_les_Discussions)

	fmt.Println("Serveur démarré sur http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
