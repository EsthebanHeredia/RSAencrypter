/**
 * Maneja el cambio entre pestañas en la interfaz de usuario
 * @param {string} tabId - El ID del contenido de la pestaña a mostrar
 */
function switchTab(tabId) {
    // Ocultar todos los contenidos de tabs
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    // Desactivar todas las pestañas
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Activar el tab seleccionado
    document.getElementById(tabId).classList.add('active');
    
    // Activar la pestaña que se hizo clic
    if (tabId === 'from-file') {
        document.querySelectorAll('.tab')[0].classList.add('active');
    } else {
        document.querySelectorAll('.tab')[1].classList.add('active');
    }
}

// Asegurar que el script se ejecute cuando el DOM esté completamente cargado
document.addEventListener('DOMContentLoaded', function() {
    // Inicialmente activar la primera pestaña
    switchTab('from-file');
});