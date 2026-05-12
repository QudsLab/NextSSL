<?php require_once $_SERVER['DOCUMENT_ROOT'] . '/common/cache.php'; ?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Browse all 776 cryptographic algorithms in NextSSL — filter by category and status, search by name.">
  <meta name="author" content="QudsLab">
  <link rel="icon" href="<?php cprint('assets/logo_glow.svg'); ?>" type="image/svg+xml">
  <title>Algorithm Browser — NextSSL</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;500;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="<?php cprint('static/style.css'); ?>">
</head>
<body>
<?php $nav_type = 'inner'; require $_SERVER['DOCUMENT_ROOT'] . '/extension/header.php'; ?>

<div class="ab-page">
  <div class="ab-shell">
    <div class="ab-hero">
      <div class="ab-hero-head">
        <div class="section-label">Algorithm Browser</div>
        <h1 class="ab-title">Compact algorithm browser</h1>
      </div>
      <p class="ab-hero-copy">Search by name or UUID, filter by status and category, then scan the catalog without wasted space.</p>
    </div>

    <div class="ab-layout">
      <main class="ab-main">
        <div class="ab-results-head">
          <div>
            <div class="ab-count-txt" id="count-txt">Loading…</div>
            <div class="ab-active-summary" id="active-summary"></div>
          </div>
        </div>

        <div class="ab-controls" aria-label="Algorithm filters">
          <div class="ab-search-block">
            <label class="ab-sec-hd" for="q">Search</label>
            <div class="ab-search-wrap">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input class="ab-search" id="q" type="search" placeholder="Search algorithms, UUIDs, categories" autocomplete="off" spellcheck="false">
            </div>
          </div>

          <div class="ab-filter-group ab-status-group">
            <div class="ab-sec-hd">Status</div>
            <div class="ab-status-list" id="status-btns">
              <button class="ab-filter-btn active" type="button" data-status="all"><span class="ab-filter-name">All</span></button>
              <button class="ab-filter-btn" type="button" data-status="active"><span class="ab-filter-name">Active</span></button>
              <button class="ab-filter-btn" type="button" data-status="legacy"><span class="ab-filter-name">Legacy / Deprecated</span></button>
              <button class="ab-filter-btn" type="button" data-status="new"><span class="ab-filter-name">New / Emerging</span></button>
            </div>
          </div>
        </div>

        <div class="ab-filter-group ab-category-group">
          <div class="ab-sec-hd">Categories</div>
          <div class="ab-category-list" id="cat-list">
            <div class="ab-spinner"><div class="ab-spin-ring"></div><span>Loading categories</span></div>
          </div>
        </div>

        <div class="ab-cards" id="cards"></div>
        <div class="ab-pagination" id="pagination"></div>
      </main>
    </div>
  </div>
</div>

<?php require $_SERVER['DOCUMENT_ROOT'] . '/extension/footer.php'; ?>

<script src="<?php cprint('static/algo_browser.js'); ?>"></script>
</body>
</html>