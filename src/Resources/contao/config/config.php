<?php

declare(strict_types=1);

/**
 * Backend-Module: LUMAS AntiSpam
 */
$GLOBALS['BE_MOD']['lumas_antispam'] = [
	'lumas_antispam_ips' => [
		'tables' => ['tl_lumas_antispam_ip_block'],
	],
	'lumas_antispam_log' => [
		'tables' => ['tl_lumas_antispam_log'],
	],
];
