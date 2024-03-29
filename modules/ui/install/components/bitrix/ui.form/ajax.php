<?php
if(!defined("B_PROLOG_INCLUDED") || B_PROLOG_INCLUDED!==true)die();

use Bitrix\Main;
use Bitrix\UI;

Main\Loader::includeModule('ui');

class CUIFormComponentAjaxController extends Main\Engine\Controller
{
	/** @var UI\Form\EntityEditorConfiguration  */
	protected static $configuration;

	protected function getConfiguration(string $categoryName = null): UI\Form\EntityEditorConfiguration
	{
		if(self::$configuration === null)
		{
			self::$configuration = new UI\Form\EntityEditorConfiguration($categoryName);
		}

		return self::$configuration;
	}

	public function saveConfigurationAction($guid, array $config, array $params, string $categoryName = '')
	{
		$this->getConfiguration($categoryName)->set($guid, $config, $params);
	}

	protected function emitOnUIFormResetScope(string $guid, array $params, string $categoryName = '')
	{
		$event = new Main\Event(
			'ui',
			'onUIFormResetScope',
			[
				'GUID' => $guid,
				'PARAMS' => $params,
				'CATEGORY_NAME' => $categoryName
			]
		);
		$event->send();
	}

	protected function emitOnUIFormSetScope(string $guid, string $scope, string $categoryName = '')
	{
		$event = new Main\Event(
			'ui',
			'onUIFormSetScope',
			[
				'GUID' => $guid,
				'SCOPE' => $scope,
				'CATEGORY_NAME' => $categoryName
			]
		);
		$event->send();
	}

	public function resetConfigurationAction($guid, array $params, string $categoryName = '')
	{
		$this->getConfiguration($categoryName)->reset($guid, $params);

		$this->emitOnUIFormResetScope($guid, $params, $categoryName);
	}

	public function setScopeAction($guid, $scope, string $categoryName = '')
	{
		$this->getConfiguration($categoryName)->setScope($guid, $scope);

		$this->emitOnUIFormSetScope($guid, $scope, $categoryName);
	}

	public function forceCommonScopeForAllAction($guid, string $categoryName = '')
	{
		$this->getConfiguration($categoryName)->forceCommonScopeForAll($guid);
	}

	public static function renderImageInputAction($moduleId, $name, $value)
	{
		/*
		$component = new UI\Controller\Response\Entity\Component('bitrix:main.file.input');
		$component->setParameters(
			array(
				'MODULE_ID' => $moduleId,
				'MAX_FILE_SIZE' => 3145728,
				'MULTIPLE'=> 'N',
				'ALLOW_UPLOAD' => 'I',
				'SHOW_AVATAR_EDITOR' => 'Y',
				'ENABLE_CAMERA' => 'N',
				'CONTROL_ID' => strtolower($name).'_uploader',
				'INPUT_NAME' => $name,
				'INPUT_VALUE' => $value
			)
		);
		$component->setFunctionParameters(array('HIDE_ICONS' => 'Y'));
		return new UI\Controller\Response\Engine\Content($component);
		*/
	}
}
