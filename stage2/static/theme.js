/* Shared light/dark theme toggle for the FLOD System console. */
(function () {
    var STORAGE_KEY = 'flod-theme';

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

    window.FlodTheme = {
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
    // onclick="fn('${value}')", those need JS-string escaping *and*
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

    window.FlodSafe = {
        escapeHtml: escapeHtml,
        jsAttr: jsAttr
    };

    /* Off-canvas sidebar drawer for narrow viewports. The button and
       backdrop are injected here rather than added to all eleven pages'
       markup, so every page picks it up from this one place. */
    function initSidebarDrawer() {
        var sidebar = document.querySelector('.sidebar');
        var titleArea = document.querySelector('.top-bar-title');
        if (!sidebar || !titleArea) return;  // login.html has no sidebar

        var backdrop = document.createElement('div');
        backdrop.className = 'sidebar-backdrop';
        document.body.appendChild(backdrop);

        var toggle = document.createElement('button');
        toggle.className = 'nav-toggle';
        toggle.type = 'button';
        toggle.setAttribute('aria-label', 'Toggle navigation');
        toggle.setAttribute('aria-expanded', 'false');
        toggle.textContent = '☰';
        titleArea.insertBefore(toggle, titleArea.firstChild);

        function setOpen(open) {
            sidebar.classList.toggle('open', open);
            backdrop.classList.toggle('visible', open);
            toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        }

        toggle.addEventListener('click', function () {
            setOpen(!sidebar.classList.contains('open'));
        });
        backdrop.addEventListener('click', function () { setOpen(false); });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') setOpen(false);
        });
        // Tapping a nav link navigates away; close so the drawer isn't
        // left open behind the next page's paint.
        sidebar.addEventListener('click', function (e) {
            if (e.target.closest('.nav-item a')) setOpen(false);
        });
        // Rotating to landscape / resizing past the breakpoint should not
        // leave a stuck backdrop over an already-visible sidebar.
        window.addEventListener('resize', function () {
            if (window.innerWidth > 900) setOpen(false);
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        updateToggleButton();
        var btn = document.getElementById('themeToggle');
        if (btn) btn.addEventListener('click', toggleTheme);
        initSidebarDrawer();
    });
})();
