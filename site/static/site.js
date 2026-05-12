let CATEGORIES, filteredAlgos, currentPage, activeCategory, activeStatus, searchQuery;
const PAGE_SIZE = 10;
function buildTabs() {
  const grid = document.getElementById('cat-tabs');
  if (!grid) return;
  CATEGORIES.forEach(cat => {
    const btn = document.createElement('button');
    btn.className = 'cat-pill' + (cat === 'All' ? ' active' : '');
    btn.textContent = cat;
    btn.onclick = () => {
      if (cat !== 'All' && activeCategory === cat) {
        activeCategory = 'All';
        currentPage = 1;
        document.querySelectorAll('.cat-pill').forEach(b => b.classList.remove('active'));
        grid.querySelector('.cat-pill').classList.add('active');
        renderTable();
        return;
      }
      activeCategory = cat;
      currentPage = 1;
      document.querySelectorAll('.cat-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderTable();
    };
    grid.appendChild(btn);
  });
}
function applyFilters() {
  filteredAlgos = ALGORITHMS.filter(a => {
    const catMatch = activeCategory === 'All' || a.category === activeCategory;
    const statusMatch = activeStatus === 'all' || a.status === activeStatus;
    const searchMatch = !searchQuery || a.name.includes(searchQuery) || a.category.toLowerCase().includes(searchQuery);
    return catMatch && statusMatch && searchMatch;
  });
}
function renderTable() {
  applyFilters();
  const total = filteredAlgos.length;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  if (currentPage > pages) currentPage = pages;
  const start = (currentPage - 1) * PAGE_SIZE;
  const page = filteredAlgos.slice(start, start + PAGE_SIZE);
  const tbody = document.getElementById('algo-tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  page.forEach(a => {
    const tr = document.createElement('tr');
    tr.className = 'algo-row';
    tr.setAttribute('data-id', a.id);
    const statusCell = a.status === 'active'
      ? '<span class="status-badge active">Active</span>'
      : `<span class="status-badge ${a.status}">${a.status === 'legacy' ? 'Legacy' : 'Emerging'}</span>`;
    tr.innerHTML = `
      <td class="algo-cell td-name">${a.name}</td>
      <td class="algo-cell td-status">${statusCell}</td>
      <td class="algo-cell td-category">${a.category}</td>
      <td class="algo-cell td-surface">#${a.id}</td>
    `;
    tbody.appendChild(tr);
  });
  const end = total === 0 ? 0 : start + page.length;
  const countDisplay = document.getElementById('count-display');
  if (countDisplay) {
    countDisplay.innerHTML = total === 0
      ? 'Showing <strong>0</strong> of <strong>0</strong> algorithms'
      : `Showing <strong>${start + 1}</strong> to <strong>${end}</strong> of <strong>${total}</strong> algorithms`;
  }
  renderPagination(total);
}
function renderPagination(total) {
  const pages = Math.ceil(total / PAGE_SIZE);
  const pag = document.getElementById('pagination');
  if (!pag) return;
  pag.innerHTML = '';
  if (pages <= 1) return;
  const prev = document.createElement('button');
  prev.className = 'page-btn';
  prev.textContent = 'Prev';
  prev.disabled = currentPage === 1;
  prev.onclick = () => {
    currentPage--;
    renderTable();
  };
  pag.appendChild(prev);
  let startPage = Math.max(1, currentPage - 1);
  let endPage = Math.min(pages, startPage + 2);
  startPage = Math.max(1, endPage - 2);
  for (let pageNum = startPage; pageNum <= endPage; pageNum++) {
    const btn = document.createElement('button');
    btn.className = 'page-btn' + (pageNum === currentPage ? ' current' : '');
    btn.textContent = String(pageNum);
    btn.onclick = () => {
      currentPage = pageNum;
      renderTable();
    };
    pag.appendChild(btn);
  }
  const info = document.createElement('span');
  info.className = 'page-info';
  info.textContent = `${currentPage} / ${pages}`;
  pag.appendChild(info);
  const next = document.createElement('button');
  next.className = 'page-btn';
  next.textContent = 'Next';
  next.disabled = currentPage === pages;
  next.onclick = () => {
    currentPage++;
    renderTable();
  };
  pag.appendChild(next);
}
function switchCodeTab(lang, btn) {
  document.querySelectorAll('.code-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.code-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('panel-' + lang).classList.add('active');
  document.getElementById('code-lang-label').textContent = lang === 'c' ? 'nextssl_kem_example.c' : 'nextssl_kem_example.py';
}
function copyCode() {
  const panel = document.querySelector('.code-panel.active pre');
  if (!panel) return;
  navigator.clipboard.writeText(panel.textContent).then(() => {
    const btn = document.getElementById('copy-code-btn');
    if (!btn) return;
    btn.textContent = 'copied';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = 'copy';
      btn.classList.remove('copied');
    }, 2000);
  });
}
function toggleMenu() {
  const menu = document.getElementById('mobile-menu');
  if (menu) menu.classList.toggle('open');
}
function animateCounters() {
  document.querySelectorAll('.counter-num').forEach(el => {
    const target = parseInt(el.dataset.target, 10);
    const duration = 1800;
    const start = performance.now();
    function step(now) {
      const progress = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(ease * target);
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });
}
function initRevealObserver() {
  const revealItems = document.querySelectorAll('.reveal');
  if (!revealItems.length) return;
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08 });
  revealItems.forEach(el => observer.observe(el));
}
function initHeroCanvas() {
  const canvas = document.getElementById('hero-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const chars = '0123456789ABCDEF'.split('');
  let cols = 0;
  let drops = [];
  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.floor(canvas.width / 18);
    drops = Array.from({ length: cols }, () => Math.random() * -50);
  }
  function draw() {
    ctx.fillStyle = 'rgba(5,5,7,0.07)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = '13px JetBrains Mono, monospace';
    drops.forEach((y, i) => {
      const char = chars[Math.floor(Math.random() * chars.length)];
      const brightness = Math.random();
      if (brightness > 0.93) ctx.fillStyle = '#00d992';
      else if (brightness > 0.7) ctx.fillStyle = 'rgba(0,217,146,0.4)';
      else ctx.fillStyle = 'rgba(0,217,146,0.12)';
      ctx.fillText(char, i * 18, y * 18);
      if (y * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0;
      drops[i] += 0.4;
    });
  }
  resize();
  window.addEventListener('resize', resize);
  setInterval(draw, 55);
}
document.addEventListener('DOMContentLoaded', function() {
  CATEGORIES = ['All', ...new Set(ALGORITHMS.map(a => a.category))];
  filteredAlgos = [...ALGORITHMS];
  currentPage = 1;
  activeCategory = 'All';
  activeStatus = 'all';
  searchQuery = '';
  buildTabs();
  renderTable();
  initRevealObserver();
  initHeroCanvas();
  setTimeout(animateCounters, 600);
  document.querySelectorAll('.pill').forEach(pill => {
    pill.onclick = () => {
      activeStatus = pill.dataset.status;
      currentPage = 1;
      document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      renderTable();
    };
  });
  const search = document.getElementById('algo-search');
  if (search) {
    search.addEventListener('input', e => {
      searchQuery = e.target.value.toLowerCase().trim();
      currentPage = 1;
      renderTable();
    });
  }
});
window.switchCodeTab = switchCodeTab;
window.copyCode = copyCode;
window.toggleMenu = toggleMenu;
