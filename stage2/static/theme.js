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

    // Escaping helpers for rendering server-supplied strings (IPs, victim
    // descriptions, etc.) into innerHTML. Every dashboard page builds its
    // tables via `.innerHTML = templateString`, so any untrusted field
    // interpolated in raw is a stored-XSS vector. Use escapeHtml() for
    // plain HTML text/attribute content, and jsAttr() specifically for
    // values embedded inside inline event-handler attributes like
    // onclick="fn('${value}')" -- those need JS-string escaping *and*
    // HTML-attribute escaping, because the browser decodes HTML entities
    // in the attribute before compiling it as the handler's script body,
    // so HTML-escaping alone does not stop a quote breakout there.
    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function jsAttr(str) {
        var jsEscaped = String(str)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/\n/g, '\\n')
            .replace(/\r/g, '\\r');
        return jsEscaped
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    window.ShieldSafe = {
        escapeHtml: escapeHtml,
        jsAttr: jsAttr
    };

    document.addEventListener('DOMContentLoaded', function () {
        updateToggleButton();
        var btn = document.getElementById('themeToggle');
        if (btn) btn.addEventListener('click', toggleTheme);
    });
})();
