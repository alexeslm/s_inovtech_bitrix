<?
if (!defined("B_PROLOG_INCLUDED") || B_PROLOG_INCLUDED !== true)
{
	die();
}

return [
	'js' => [
		'./dist/lazyload.bundle.js',
	],
	'rel' => [
		'main.polyfill.core',
		'ui.vue3',
		'main.polyfill.intersectionobserver',
	],
	'skip_core' => true,
];