/* Shared light/dark theme toggle for the Shield Gateway console. */
(function () {
    var STORAGE_KEY = 'shield-theme';

    function currentTheme() {
        return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    function updateToggleButton() {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;
        btn.textContent = currentTheme() === 'dark' ? 'Light Mode' : 'Dark Mode';
    }

    function toggleTheme() {
        var next = currentTheme() === 'dark' ? 'light' : 'dark';
        localStorage.setItem(STORAGE_KEY, next);
        applyTheme(next);
        updateToggleButton();
        document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: next } }));
    }

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    window.ShieldTheme = {
        toggle: toggleTheme,
        current: currentTheme,
        cssVar: cssVar
    };

    document.addEventListener('DOMContentLoaded', function () {
        updateToggleButton();
        var btn = document.getElementById('themeToggle');
        if (btn) btn.addEventListener('click', toggleTheme);
    });
})();
