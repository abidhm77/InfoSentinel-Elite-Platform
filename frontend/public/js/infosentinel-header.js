class InfoSentinelHeader extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
    this.bindEvents();
  }

  render() {
    const template = document.createElement('template');
    template.innerHTML = `
      <style>
        :host {
          --bg: rgba(12, 16, 24, 0.65);
          --glass: rgba(18, 24, 38, 0.55);
          --border: rgba(74, 144, 226, 0.18);
          --text: #e6edf3;
          --muted: #a1adc0;
          --accent: #4fc3f7;
          --accent-2: #a78bfa;
          --danger: #ff5370;
          --shadow-glow: 0 8px 24px rgba(79, 195, 247, 0.15), 0 0 40px rgba(167, 139, 250, 0.15);
          --radius: 14px;
          --transition: 220ms cubic-bezier(.2,.6,.2,1);
          --blur: 14px;
          --header-height: 68px;
          position: relative;
          display: block;
          z-index: 1000;
        }

        .header-wrap {
          position: sticky;
          top: 0;
          inset-inline: 0;
          height: var(--header-height);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 10px 16px;
          background: transparent;
          -webkit-backdrop-filter: blur(var(--blur));
          backdrop-filter: blur(var(--blur));
        }

        .header {
          width: min(1200px, 100%);
          height: 100%;
          display: grid;
          grid-template-columns: auto 1fr auto;
          align-items: center;
          gap: 16px;
          padding: 10px 16px;
          border-radius: var(--radius);
          background: linear-gradient(180deg, var(--glass), rgba(12,16,24,0.35));
          border: 1px solid var(--border);
          box-shadow: var(--shadow-glow), 0 1px 0 rgba(255,255,255,0.04) inset;
        }

        /* Brand */
        .brand {
          display: flex;
          align-items: center;
          gap: 10px;
          color: var(--text);
          text-decoration: none;
          user-select: none;
        }
        .brand-logo {
          width: 36px;
          height: 36px;
          display: grid;
          place-items: center;
          border-radius: 10px;
          background: radial-gradient(120px 60px at 30% 20%, rgba(79,195,247,0.25), transparent 60%),
                      radial-gradient(140px 80px at 70% 70%, rgba(167,139,250,0.2), transparent 60%);
          box-shadow: 0 0 0 1px rgba(79,195,247,0.25) inset;
        }
        .brand svg {
          width: 22px;
          height: 22px;
          color: var(--accent);
          filter: drop-shadow(0 0 8px rgba(79,195,247,0.35));
        }
        .brand-name {
          font-weight: 700;
          letter-spacing: 0.3px;
          font-size: 1.05rem;
          background: linear-gradient(90deg, #e6f7ff, #c7d2fe);
          -webkit-background-clip: text;
          background-clip: text;
          color: transparent;
        }

        /* Navigation */
        nav {
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 6px;
        }
        .nav-link {
          position: relative;
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 10px 12px;
          font-size: 0.93rem;
          border-radius: 10px;
          color: var(--muted);
          text-decoration: none;
          transition: transform var(--transition), color var(--transition), background var(--transition), box-shadow var(--transition);
        }
        .nav-link:hover {
          color: var(--text);
          background: linear-gradient(180deg, rgba(79,195,247,0.1), rgba(167,139,250,0.08));
          box-shadow: 0 8px 24px rgba(79,195,247,0.08), 0 0 24px rgba(167,139,250,0.08);
        }
        .nav-link.active {
          color: #0b1220;
          background: linear-gradient(180deg, rgba(79,195,247,0.9), rgba(167,139,250,0.9));
          box-shadow: 0 6px 18px rgba(79,195,247,0.25), 0 0 30px rgba(167,139,250,0.3);
        }
        .glow-dot {
          display: inline-block;
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: radial-gradient(circle at 50% 50%, #6ee7ff 0%, #4fc3f7 35%, transparent 65%);
          box-shadow: 0 0 12px rgba(79,195,247,0.6);
        }

        /* Actions */
        .actions {
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .icon-btn {
          display: grid;
          place-items: center;
          width: 38px;
          height: 38px;
          border-radius: 12px;
          color: var(--muted);
          border: 1px solid rgba(255,255,255,0.06);
          background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0));
          transition: transform var(--transition), color var(--transition), background var(--transition), box-shadow var(--transition);
          cursor: pointer;
        }
        .icon-btn:hover {
          color: var(--text);
          background: linear-gradient(180deg, rgba(79,195,247,0.08), rgba(167,139,250,0.05));
          box-shadow: 0 8px 20px rgba(79,195,247,0.1), 0 0 20px rgba(167,139,250,0.1);
        }

        .avatar {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 6px 8px;
          border-radius: 12px;
          border: 1px solid rgba(255,255,255,0.06);
          background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0));
          color: var(--text);
          cursor: pointer;
          transition: background var(--transition), box-shadow var(--transition);
        }
        .avatar:hover {
          background: linear-gradient(180deg, rgba(79,195,247,0.08), rgba(167,139,250,0.05));
          box-shadow: 0 8px 20px rgba(79,195,247,0.1), 0 0 20px rgba(167,139,250,0.1);
        }
        .avatar-img {
          width: 32px;
          height: 32px;
          border-radius: 10px;
          background: radial-gradient(circle at 30% 30%, #4fc3f7, #a78bfa);
          box-shadow: 0 0 0 1px rgba(255,255,255,0.06) inset;
        }
        .caret {
          width: 10px;
          height: 10px;
          margin-left: 4px;
          border: solid var(--muted);
          border-width: 0 1.5px 1.5px 0;
          display: inline-block;
          padding: 2.5px;
          transform: rotate(45deg);
          transition: transform var(--transition), border-color var(--transition);
        }
        .avatar.open .caret {
          transform: rotate(-135deg);
          border-color: var(--text);
        }

        /* Dropdown */
        .dropdown {
          position: absolute;
          top: calc(100% + 10px);
          right: 0;
          width: 240px;
          padding: 10px;
          border-radius: 14px;
          background: linear-gradient(180deg, rgba(18,24,38,0.95), rgba(12,16,24,0.92));
          border: 1px solid var(--border);
          box-shadow: var(--shadow-glow), 0 20px 40px rgba(0,0,0,0.35);
          -webkit-backdrop-filter: blur(var(--blur));
          backdrop-filter: blur(var(--blur));
          opacity: 0;
          transform: translateY(-6px) scale(0.98);
          pointer-events: none;
          transition: opacity var(--transition), transform var(--transition);
        }
        .dropdown.open {
          opacity: 1;
          transform: translateY(0) scale(1);
          pointer-events: auto;
        }
        .dropdown .section-title {
          font-size: 0.74rem;
          text-transform: uppercase;
          letter-spacing: 0.08em;
          color: var(--muted);
          padding: 6px 10px;
        }
        .dropdown .item {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 10px 12px;
          border-radius: 10px;
          color: var(--text);
          text-decoration: none;
          transition: background var(--transition), color var(--transition), transform var(--transition);
        }
        .dropdown .item:hover {
          background: linear-gradient(180deg, rgba(79,195,247,0.1), rgba(167,139,250,0.08));
          transform: translateX(2px);
        }
        .dropdown .divider {
          height: 1px;
          background: linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent);
          margin: 8px 6px;
        }

        /* Mobile */
        .hamburger {
          display: none;
        }
        .mobile-menu {
          position: absolute;
          top: calc(100% + 10px);
          left: 0;
          right: 0;
          padding: 12px;
          border-radius: 14px;
          background: linear-gradient(180deg, rgba(18,24,38,0.95), rgba(12,16,24,0.92));
          border: 1px solid var(--border);
          box-shadow: var(--shadow-glow), 0 20px 40px rgba(0,0,0,0.35);
          -webkit-backdrop-filter: blur(var(--blur));
          backdrop-filter: blur(var(--blur));
          opacity: 0;
          transform: translateY(-6px) scale(0.98);
          pointer-events: none;
          transition: opacity var(--transition), transform var(--transition);
        }
        .mobile-menu.open {
          opacity: 1;
          transform: translateY(0) scale(1);
          pointer-events: auto;
        }
        .mobile-item {
          display: block;
          padding: 12px 14px;
          border-radius: 10px;
          color: var(--text);
          text-decoration: none;
          transition: background var(--transition), transform var(--transition);
        }
        .mobile-item:hover {
          background: linear-gradient(180deg, rgba(79,195,247,0.1), rgba(167,139,250,0.08));
          transform: translateY(-1px);
        }

        @media (max-width: 900px) {
          nav { display: none; }
          .hamburger { display: grid; }
        }
      </style>
      <div class="header-wrap">
        <header class="header">
          <a href="index-unified.html" class="brand" aria-label="InfoSentinel Home">
            <span class="brand-logo" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="M12 21c4.971 0 9-4.029 9-9s-4.029-9-9-9-9 4.029-9 9 4.029 9 9 9Z" stroke="currentColor" stroke-width="1.6"/>
                <path d="M12 6v12" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
                <path d="M8 10h8M8 14h8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
              </svg>
            </span>
            <span class="brand-name">InfoSentinel</span>
          </a>

          <nav aria-label="Primary">
            <a class="nav-link active" href="#dashboard"><span class="glow-dot"></span> Dashboard</a>
            <a class="nav-link" href="#scans">Scans</a>
            <a class="nav-link" href="#vulnerabilities">Vulnerabilities</a>
            <a class="nav-link" href="#reports">Reports</a>
          </nav>

          <div class="actions">
            <button class="icon-btn hamburger" aria-label="Open menu" aria-expanded="false" aria-controls="mobile-menu">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                <path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
              </svg>
            </button>
            <div class="avatar" id="avatar" tabindex="0" role="button" aria-haspopup="menu" aria-expanded="false">
              <div class="avatar-img" aria-hidden="true"></div>
              <span class="label">Admin</span>
              <i class="caret"></i>
              <div class="dropdown" id="dropdown" role="menu" aria-label="User menu">
                <div class="section-title">Account</div>
                <a href="#profile" class="item">Profile</a>
                <a href="#settings" class="item">Settings</a>
                <div class="divider"></div>
                <a href="#logout" class="item" style="color: var(--danger)">Sign out</a>
              </div>
            </div>
          </div>

          <div class="mobile-menu" id="mobile-menu" role="menu" aria-label="Mobile navigation">
            <a class="mobile-item" href="#dashboard">Dashboard</a>
            <a class="mobile-item" href="#scans">Scans</a>
            <a class="mobile-item" href="#vulnerabilities">Vulnerabilities</a>
            <a class="mobile-item" href="#reports">Reports</a>
          </div>
        </header>
      </div>
    `;
    this.shadowRoot.appendChild(template.content.cloneNode(true));
  }

  bindEvents() {
    const dropdown = this.shadowRoot.getElementById('dropdown');
    const avatar = this.shadowRoot.getElementById('avatar');
    const hamburger = this.shadowRoot.querySelector('.hamburger');
    const mobileMenu = this.shadowRoot.getElementById('mobile-menu');
    const navLinks = this.shadowRoot.querySelectorAll('.nav-link');

    // Toggle dropdown
    const closeDropdown = () => {
      avatar.classList.remove('open');
      dropdown.classList.remove('open');
      avatar.setAttribute('aria-expanded', 'false');
    };
    const openDropdown = () => {
      avatar.classList.add('open');
      dropdown.classList.add('open');
      avatar.setAttribute('aria-expanded', 'true');
    };

    avatar.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = dropdown.classList.contains('open');
      isOpen ? closeDropdown() : openDropdown();
    });
    avatar.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const isOpen = dropdown.classList.contains('open');
        isOpen ? closeDropdown() : openDropdown();
      }
      if (e.key === 'Escape') closeDropdown();
    });

    // Toggle mobile menu
    const closeMobile = () => {
      mobileMenu.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    };
    const openMobile = () => {
      mobileMenu.classList.add('open');
      hamburger.setAttribute('aria-expanded', 'true');
    };
    hamburger.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = mobileMenu.classList.contains('open');
      isOpen ? closeMobile() : openMobile();
    });

    // Active nav state (demo)
    navLinks.forEach((link) => {
      link.addEventListener('click', (e) => {
        navLinks.forEach(l => l.classList.remove('active'));
        e.currentTarget.classList.add('active');
      });
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      const withinComponent = this.contains(e.target) || this.shadowRoot.contains(e.target);
      if (!withinComponent) {
        dropdown.classList.remove('open');
        this.shadowRoot.getElementById('avatar').classList.remove('open');
        mobileMenu.classList.remove('open');
        hamburger.setAttribute('aria-expanded', 'false');
      }
    });

    // Close on resize
    window.addEventListener('resize', () => {
      dropdown.classList.remove('open');
      this.shadowRoot.getElementById('avatar').classList.remove('open');
      mobileMenu.classList.remove('open');
      hamburger.setAttribute('aria-expanded', 'false');
    });
  }
}

customElements.define('infosentinel-header', InfoSentinelHeader);