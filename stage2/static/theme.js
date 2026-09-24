/* Shared light/dark theme toggle for the FLOD System console, plus V10's
   selectable design family (which of the three redesign directions is
   active). Two independent axes: data-theme (light/dark) and data-design
   (operations/terminal/saas), combined in base.css as
   :root[data-design="X"][data-theme="Y"]. */
(function () {
    var THEME_STORAGE_KEY = 'flod-theme';
    var DESIGN_STORAGE_KEY = 'flod-design';
    var DESIGNS = ['operations', 'terminal', 'saas'];
    var DEFAULT_DESIGN = 'operations';

    function currentTheme() {
        return document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
    }

    function currentDesign() {
        var d = document.documentElement.getAttribute('data-design');
        return DESIGNS.indexOf(d) !== -1 ? d : DEFAULT_DESIGN;
    }

    function applyDesign(design) {
        if (DESIGNS.indexOf(design) === -1) design = DEFAULT_DESIGN;
        document.documentElement.setAttribute('data-design', design);
    }

    function setDesign(design) {
        localStorage.setItem(DESIGN_STORAGE_KEY, design);
        applyDesign(design);
        document.dispatchEvent(new CustomEvent('designchange', { detail: { design: design } }));
    }

    function updateToggleButton() {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;
        btn.textContent = currentTheme() === 'dark' ? 'Light Mode' : 'Dark Mode';
    }

    function toggleTheme() {
        var next = currentTheme() === 'dark' ? 'light' : 'dark';
        localStorage.setItem(THEME_STORAGE_KEY, next);
        applyTheme(next);
        updateToggleButton();
        document.dispatchEvent(new CustomEvent('themechange', { detail: { theme: next } }));
    }

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    // V10: briefly applies one of base.css's pulse classes (badge-pulse,
    // stat-pulse) to an element, for the moment a live-polled value
    // actually changed, not on every poll regardless of value. Callers
    // are expected to only invoke this when the new value differs from
    // the last one they rendered; this helper does not check that
    // itself, since it doesn't know what "the value" means for a given
    // caller. Restarts cleanly if called again before the previous pulse
    // finished (removing then re-adding the class in the next frame,
    // since re-adding an already-present class does not restart a CSS
    // animation).
    function pulse(el, className) {
        if (!el) return;
        el.classList.remove(className);
        // eslint-disable-next-line no-unused-expressions
        void el.offsetWidth; // force reflow so the removal above takes effect
        el.classList.add(className);
    }

    // Unlike data-theme, which every page bootstraps inline in <head>
    // before this file loads (avoiding a flash of the wrong theme), this
    // runs wherever this <script src="theme.js"> tag sits on the page,
    // which today is near the end of <body>. A brief flash of the
    // default design on load is a known, accepted gap until an inline
    // per-page bootstrap is added to match data-theme's pattern, tracked
    // as part of the still-open per-page redesign work.
    applyDesign(localStorage.getItem(DESIGN_STORAGE_KEY) || DEFAULT_DESIGN);

    window.FlodTheme = {
        toggle: toggleTheme,
        current: currentTheme,
        cssVar: cssVar,
        pulse: pulse,
        designs: DESIGNS.slice(),
        currentDesign: currentDesign,
        setDesign: setDesign
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

    // Every page carries the same footer, so the version is filled in here
    // rather than duplicated into each one. Silent on failure: an unlabelled
    // footer is better than an error on a page that is otherwise working.
    function showVersion() {
        var el = document.getElementById('flodVersion');
        if (!el) return;
        fetch('/api/version')
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) { if (d && d.version) el.textContent = 'v' + d.version; })
            .catch(function () {});
    }

    // Same reasoning as showVersion(): one place fills a badge every page's
    // nav can carry, rather than duplicating the poll into each page. Silent
    // on failure or when a page has no #autoLabelBadge element at all.
    function showAutoLabelBadge() {
        var el = document.getElementById('autoLabelBadge');
        if (!el) return;
        fetch('/api/auto-label/runs')
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (d) {
                if (!d || !d.runs || !d.runs.length) {
                    el.style.display = 'none';
                    return;
                }
                var total = d.runs.reduce(function (sum, run) { return sum + run.rows_labeled; }, 0);
                el.textContent = total;
                el.style.display = '';
            })
            .catch(function () {});
    }

    // Debugging aid only, not part of the V10 design: lets the three
    // design families be compared in a browser next to the existing
    // theme toggle, without console commands. Injected here, on every
    // page that loads theme.js, rather than duplicated into each page's
    // markup. Remove once a real settings surface for this exists.
    function initDesignSwitcher() {
        var anchor = document.getElementById('themeToggle');
        if (!anchor) return;
        var sel = document.createElement('select');
        sel.id = 'designSwitcher';
        sel.title = 'Design family (debug)';
        sel.style.cssText = 'position:fixed;top:20px;right:70px;z-index:1000;' +
            'background:var(--bg-surface);color:var(--text-primary);border:1px solid var(--border-color);' +
            'border-radius:var(--radius-sm);padding:6px 10px;font-family:var(--font-sans);font-size:0.78rem;';
        DESIGNS.forEach(function (name) {
            var opt = document.createElement('option');
            opt.value = name;
            opt.textContent = {
                operations: 'Operations Console',
                terminal: 'Security Terminal',
                saas: 'Modern SaaS'
            }[name] || name;
            sel.appendChild(opt);
        });
        sel.value = currentDesign();
        sel.addEventListener('change', function () { setDesign(sel.value); });
        document.body.appendChild(sel);
    }

    document.addEventListener('DOMContentLoaded', function () {
        updateToggleButton();
        initDesignSwitcher();
        var btn = document.getElementById('themeToggle');
        if (btn) btn.addEventListener('click', toggleTheme);
        initSidebarDrawer();
        showVersion();
        showAutoLabelBadge();
    });
})();
