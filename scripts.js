   // Fonction pour afficher/masquer le popover
   function togglePopover(postId) {
    var popover = document.getElementById('popover-' + postId);
    
    // Vérifie si le popover est déjà visible
    if (popover.style.display === 'none' || popover.style.display === '') {
        // Trouver la position du bouton Commenter
        var button = document.querySelector(`button[onclick="togglePopover(${postId})"]`);
        var buttonRect = button.getBoundingClientRect();
        
        // Positionner le popover au-dessus ou à côté du bouton
        popover.style.left = buttonRect.left + 'px';
        popover.style.top = buttonRect.top + buttonRect.height + 5 + 'px';  // Juste en dessous du bouton
        popover.style.display = 'block';
    } else {
        popover.style.display = 'none';
    }
}