(function () {
  'use strict';

  const PER_PAGE = 35;
  const CAT_LABELS = {
    a: 'Encoding & Checksum',
    b: 'Hash / Digest / XOF',
    c: 'Password KDFs',
    d: 'Symmetric Block Ciphers',
    e: 'Stream Ciphers',
    f: 'Block Cipher Modes',
    g: 'AEAD Algorithms',
    h: 'MAC Algorithms',
    i: 'Key Derivation Functions',
    j: 'Key Agreement / KEM',
    k: 'Digital Signatures',
    l: 'PQ Digital Signatures',
    m: 'Stateful Hash Signatures',
    n: 'Threshold / MPC',
    o: 'Lightweight Crypto',
    p: 'DRBG / RNG',
    q: 'ZK Proofs / HE',
    r: 'Protocol Primitives',
    s: 'PKI / Certificates',
    t: 'Hardware / HSM / TEE',
    u: 'Verifiable Delay Functions',
    v: 'Advanced Primitives'
  };
  const STATUS_LABELS = {
    all: 'All statuses',
    active: 'Active',
    legacy: 'Legacy / Deprecated',
    new: 'New / Emerging'
  };
  const CARD_STATUS_LABELS = {
    active: 'ACTIVE',
    legacy: 'LEGACY',
    new: 'NEW'
  };

  const state = {
    allAlgos: [],
    categoryThemes: {},
    activeCat: 'all',
    activeStatus: 'all',
    query: '',
    page: 1
  };

  const elements = {
    search: document.getElementById('q'),
    catList: document.getElementById('cat-list'),
    statusList: document.getElementById('status-btns'),
    count: document.getElementById('count-txt'),
    summary: document.getElementById('active-summary'),
    cards: document.getElementById('cards'),
    pagination: document.getElementById('pagination')
  };

  function esc(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function normalize(value) {
    return String(value ?? '').toLowerCase();
  }

  function extractCategoryThemes(data) {
    const themes = {};
    for (const categoryGroup of Object.values(data)) {
      if (!categoryGroup?.label) {
        continue;
      }
      themes[categoryGroup.label] = {
        bgColor: categoryGroup.bg_color || '',
        accentColor: categoryGroup.accent_color || ''
      };
    }
    return themes;
  }

  function flattenData(data) {
    const flat = [];
    for (const [categoryName, categoryGroup] of Object.entries(data)) {
      const label = categoryGroup.label || '';
      for (const status of ['active', 'legacy', 'new']) {
        const entries = categoryGroup[status] || [];
        for (const algo of entries) {
          flat.push({
            name: algo.name,
            uuid: algo.uuid,
            label,
            cat: categoryName,
            status
          });
        }
      }
    }
    return flat;
  }

  function getCategoryEntries() {
    const counts = {};
    for (const algo of state.allAlgos) {
      counts[algo.label] = (counts[algo.label] || 0) + 1;
    }

    const ordered = Object.entries(CAT_LABELS).map(([label, name]) => ({
      label,
      name,
      count: counts[label] || 0,
      theme: state.categoryThemes[label] || null
    }));
    const extras = Object.keys(counts)
      .filter(label => !CAT_LABELS[label])
      .sort()
      .map(label => ({
        label,
        name: label.toUpperCase(),
        count: counts[label] || 0,
        theme: state.categoryThemes[label] || null
      }));

    return [{ label: 'all', name: 'All', count: state.allAlgos.length, theme: null }, ...ordered, ...extras];
  }

  function getStatusCounts() {
    const counts = {
      all: state.allAlgos.length,
      active: 0,
      legacy: 0,
      new: 0
    };

    for (const algo of state.allAlgos) {
      counts[algo.status] = (counts[algo.status] || 0) + 1;
    }

    return counts;
  }

  function buildFilters() {
    const categoryEntries = getCategoryEntries();
    elements.catList.innerHTML = categoryEntries.map(entry => {
      const isActive = entry.label === state.activeCat;
      const classes = ['ab-filter-btn'];
      if (entry.label === 'all') {
        classes.push('ab-filter-all');
      }
      if (isActive) {
        classes.push('active');
      }
      const style = entry.theme?.bgColor && entry.theme?.accentColor
        ? ` style="--ab-cat-bg:${esc(entry.theme.bgColor)};--ab-cat-accent:${esc(entry.theme.accentColor)}"`
        : '';
      return `<button class="${classes.join(' ')}" type="button" data-cat="${esc(entry.label)}" title="${esc(entry.name)}">
        <span class="ab-filter-name"${style}>${esc(entry.name)}</span>
      </button>`;
    }).join('');

    const statusCounts = getStatusCounts();
    elements.statusList.querySelectorAll('[data-status]').forEach(button => {
      const status = button.dataset.status;
      const label = status === 'all' ? 'All' : STATUS_LABELS[status];
      button.innerHTML = `
        <span class="ab-filter-name">${esc(label)}</span>
        <span class="ab-filter-meta">${statusCounts[status] || 0}</span>
      `;
      button.classList.toggle('active', status === state.activeStatus);
    });
  }

  function filteredAlgos() {
    const query = normalize(state.query).trim();
    return state.allAlgos.filter(algo => {
      if (state.activeCat !== 'all' && algo.label !== state.activeCat) {
        return false;
      }
      if (state.activeStatus !== 'all' && algo.status !== state.activeStatus) {
        return false;
      }
      if (!query) {
        return true;
      }

      return normalize(algo.name).includes(query)
        || normalize(algo.uuid).includes(query)
        || normalize(algo.cat).includes(query)
        || normalize(CAT_LABELS[algo.label] || '').includes(query);
    });
  }

  function renderSummary(total, start, end) {
    const category = state.activeCat === 'all' ? 'All categories' : (CAT_LABELS[state.activeCat] || state.activeCat.toUpperCase());
    const status = STATUS_LABELS[state.activeStatus];
    const parts = [category, status, `Showing ${start}-${end}`];
    if (state.query.trim()) {
      parts.push(`Query: "${state.query.trim()}"`);
    }
    elements.summary.textContent = parts.join('  /  ');
    elements.summary.hidden = total === 0;
  }

  function renderCard(algo) {
    const detailUrl = `/algo/detail.php?uuid=${encodeURIComponent(algo.uuid)}&cat=${encodeURIComponent(algo.label)}`;
    const statusText = CARD_STATUS_LABELS[algo.status] || STATUS_LABELS[algo.status] || algo.status;
    return `<a class="ab-card" href="${detailUrl}">
      <div class="ab-card-head">
        <div class="ab-card-name">${esc(algo.name)}</div>
        <div class="ab-card-status">
          <span class="ab-badge ${esc(algo.status)}">${esc(statusText)}</span>
        </div>
      </div>
      <div class="ab-card-body">
        <div class="ab-card-meta">${esc(algo.cat)}</div>
      </div>
    </a>`;
  }

  function paginationRange(current, totalPages) {
    if (totalPages <= 7) {
      return Array.from({ length: totalPages }, (_, index) => index + 1);
    }

    const pages = [1];
    if (current > 3) {
      pages.push('ellipsis-left');
    }
    for (let page = Math.max(2, current - 1); page <= Math.min(totalPages - 1, current + 1); page += 1) {
      pages.push(page);
    }
    if (current < totalPages - 2) {
      pages.push('ellipsis-right');
    }
    pages.push(totalPages);
    return pages;
  }

  function renderPagination(totalPages) {
    if (totalPages <= 1) {
      elements.pagination.innerHTML = '';
      return;
    }

    const range = paginationRange(state.page, totalPages);
    const items = [];
    items.push(`<button class="ab-pg-btn" type="button" data-page="${state.page - 1}" ${state.page === 1 ? 'disabled' : ''}>Prev</button>`);
    for (const item of range) {
      if (typeof item === 'string') {
        items.push('<span class="ab-pg-ellipsis">...</span>');
      } else {
        items.push(`<button class="ab-pg-btn${item === state.page ? ' active' : ''}" type="button" data-page="${item}">${item}</button>`);
      }
    }
    items.push(`<button class="ab-pg-btn" type="button" data-page="${state.page + 1}" ${state.page === totalPages ? 'disabled' : ''}>Next</button>`);
    elements.pagination.innerHTML = items.join('');
  }

  function render() {
    const list = filteredAlgos();
    const total = list.length;
    const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
    state.page = Math.min(state.page, totalPages);

    const start = total === 0 ? 0 : ((state.page - 1) * PER_PAGE) + 1;
    const end = total === 0 ? 0 : Math.min(total, state.page * PER_PAGE);
    const currentSlice = list.slice(start === 0 ? 0 : start - 1, end);

    const category = state.activeCat === 'all' ? 'all categories' : (CAT_LABELS[state.activeCat] || state.activeCat.toUpperCase());
    elements.count.innerHTML = total === 0
      ? 'No algorithms match the current filters.'
      : `<strong>${total}</strong> algorithm${total === 1 ? '' : 's'} in ${esc(category)}`;

    renderSummary(total, start, end);

    elements.cards.innerHTML = currentSlice.length
      ? currentSlice.map(renderCard).join('')
      : '<div class="ab-empty">No algorithms match your filters. Clear the query or switch category.</div>';

    renderPagination(totalPages);
  }

  function setActiveFilter(group, value) {
    if (group === 'cat') {
      state.activeCat = value;
      elements.catList.querySelectorAll('[data-cat]').forEach(button => {
        button.classList.toggle('active', button.dataset.cat === value);
      });
    }

    if (group === 'status') {
      state.activeStatus = value;
      elements.statusList.querySelectorAll('[data-status]').forEach(button => {
        button.classList.toggle('active', button.dataset.status === value);
      });
    }

    state.page = 1;
    render();
  }

  function bindEvents() {
    elements.search.addEventListener('input', event => {
      state.query = event.target.value;
      state.page = 1;
      render();
    });

    elements.catList.addEventListener('click', event => {
      const button = event.target.closest('[data-cat]');
      if (!button) {
        return;
      }
      setActiveFilter('cat', button.dataset.cat);
    });

    elements.statusList.addEventListener('click', event => {
      const button = event.target.closest('[data-status]');
      if (!button) {
        return;
      }
      setActiveFilter('status', button.dataset.status);
    });

    elements.pagination.addEventListener('click', event => {
      const button = event.target.closest('[data-page]');
      if (!button || button.disabled) {
        return;
      }
      state.page = Number(button.dataset.page);
      render();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  function renderFailure() {
    elements.count.textContent = '';
    elements.summary.textContent = '';
    elements.cards.innerHTML = '<div class="ab-empty">Failed to load algorithms. Please try again.</div>';
    elements.pagination.innerHTML = '';
  }

  function init() {
    bindEvents();
    fetch('/api/detail.php')
      .then(response => response.json())
      .then(payload => {
        if (payload.status !== 'success') {
          throw new Error('Algorithm API returned an error state.');
        }
        state.categoryThemes = extractCategoryThemes(payload.data);
        state.allAlgos = flattenData(payload.data);
        buildFilters();
        render();
      })
      .catch(() => {
        renderFailure();
      });
  }

  init();
})();
