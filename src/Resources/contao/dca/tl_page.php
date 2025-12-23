<?php

declare(strict_types=1);

use Contao\CoreBundle\DataContainer\PaletteManipulator;

/*
 * Palette: nur Root-Seiten
 */
PaletteManipulator::create()
	->addLegend('lumas_antispam_legend', 'publish_legend', PaletteManipulator::POSITION_AFTER)
	->addField([
		// IP / Global
		'lumas_antispam_ip_block',
		'lumas_antispam_ip_block_ttl',

		// Time-based
		'lumas_antispam_minDelay',
		'lumas_antispam_blockTime',

		// Text / Language
		'lumas_antispam_language',
		'lumas_antispam_stopwordCount',
		'lumas_antispam_maxLinks',
		'lumas_antispam_minLen',
	], 'lumas_antispam_legend', PaletteManipulator::POSITION_APPEND)
	->applyToPalette('root', 'tl_page')
	->applyToPalette('rootfallback', 'tl_page');

/*
 * Felder
 */

$GLOBALS['TL_DCA']['tl_page']['fields']['lumas_antispam_ip_block'] = [
	'label'     => &$GLOBALS['TL_LANG']['tl_page']['lumas_antispam_ip_block'],
	'inputType' => 'checkbox',
	'eval'      => ['tl_class' => 'w50 m12'],
	'sql'       => "char(1) NOT NULL default ''",
];

$GLOBALS['TL_DCA']['tl_page']['fields']['lumas_antispam_language'] = [
	'label'     => &$GLOBALS['TL_LANG']['tl_page']['lumas_antispam_language'],
	'inputType' => 'select',
	'options'   => ['de', 'en', 'fr', 'es', 'it'],
	'reference' => &$GLOBALS['TL_LANG']['tl_page']['lumas_antispam_languages'],
	'eval'      => [
		'tl_class'           => 'w50',
		'includeBlankOption' => true,
		'chosen'             => true,
	],
	'sql'       => "varchar(2) NOT NULL default ''",
];

// Numerische Root-Defaults
$numericDefaults = [
	'ip_block_ttl'  => 24,
	'minDelay'      => 15,
	'blockTime'     => 30,
	'stopwordCount' => 2,
	'maxLinks'      => 1,
	'minLen'        => 15,
];

foreach ($numericDefaults as $field => $placeholder) {
	$GLOBALS['TL_DCA']['tl_page']['fields']['lumas_antispam_' . $field] = [
		'label'     => &$GLOBALS['TL_LANG']['tl_page']['lumas_antispam_' . $field],
		'inputType' => 'text',
		'eval'      => [
			'rgxp'        => 'digit',
			'tl_class'    => 'w50',
			'nospace'     => true,
			'placeholder' => (string) $placeholder,
		],
		'sql'       => "int(10) unsigned NULL",
	];
}
