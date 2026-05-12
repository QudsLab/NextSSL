<?php
/**
 * Shared site header — nav + mobile menu
 * Set before including:
 *   $nav_type  = 'home'  | 'inner'   (default: 'home')
 *   $nav_links = [['href'=>'…','label'=>'…'], …]  (optional override)
 *
 * Always call: require_once $_SERVER['DOCUMENT_ROOT'] . '/cache.php';
 * before including this file.
 */
$nav_type = $nav_type ?? 'home';
$nav_links = $nav_links ?? null;

if ($nav_links === null) {
    if ($nav_type === 'home') {
        $nav_links = [
            ['href' => '#why', 'label' => 'Why NextSSL'],
            ['href' => '#algorithms', 'label' => 'Algorithms'],
            ['href' => '/algo/', 'label' => 'Browser'],
            ['href' => '#timeline', 'label' => 'Roadmap'],
            ['href' => '#usecases', 'label' => 'Use Cases'],
            ['href' => '#compare', 'label' => 'Compare'],
        ];
    } else {
        $nav_links = [
            ['href' => '/', 'label' => 'Home'],
            ['href' => '/algo/', 'label' => 'Browser'],
            ['href' => '/#timeline', 'label' => 'Roadmap'],
        ];
    }
}
$logo_href = ($nav_type === 'home') ? '#hero' : '/';
?>
<!-- Navigation -->
<nav>
    <div class="nav-inner">
        <a href="<?php echo $logo_href; ?>" class="nav-logo">
            <div class="logo-mark">
                <img src="<?php cprint('assets/logo_glow.svg'); ?>" width="28" height="28" alt="NextSSL"
                    style="display:block">
            </div>
            NextSSL
        </a>
        <div class="nav-links">
            <?php foreach ($nav_links as $l): ?>
                <a href="<?php echo htmlspecialchars($l['href']); ?>"><?php echo htmlspecialchars($l['label']); ?></a>
            <?php endforeach; ?>
        </div>
        <div class="nav-cta">
            <a href="https://github.com/QudsLab/NextSSL" target="_blank" rel="noopener" class="gh-star">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polygon
                        points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" />
                </svg>
                Star
            </a>
            <a href="https://github.com/QudsLab/NextSSL" target="_blank" rel="noopener" class="btn-primary">GitHub</a>
        </div>
        <div class="hamburger" onclick="document.getElementById('mobile-menu').classList.toggle('open')">
            <span></span><span></span><span></span>
        </div>
    </div>
</nav>
<div class="mobile-menu" id="mobile-menu">
    <?php foreach ($nav_links as $l): ?>
        <a href="<?php echo htmlspecialchars($l['href']); ?>"
            onclick="document.getElementById('mobile-menu').classList.remove('open')"><?php echo htmlspecialchars($l['label']); ?></a>
    <?php endforeach; ?>
    <a href="https://github.com/QudsLab/NextSSL" target="_blank">View on GitHub</a>
</div>