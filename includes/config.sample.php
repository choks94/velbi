<?php
/*
 * Copy this file to config.php (same folder) and fill in the values.
 * config.php is not in git, so create it once directly on the server
 * (Hostinger: hPanel → File Manager → public_html/includes/config.php).
 */
return [
    // Bcrypt hash of the /admin/ password — keep the single quotes.
    // Generate it on macOS/Linux (asks for the password, prints the hash):
    //   htpasswd -nBC 12 "" | tr -d ':\n'
    'admin_password_hash' => '',

    // Optional: folder for coupon data. Defaults to data/ next to this folder.
    // 'data_dir' => '/home/u123456789/domains/velbi.shop/velbi-data',
];
