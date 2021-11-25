<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerSdk\Sdk\Presentation\Console\Commands;

use SprykerSdk\Sdk\Core\Appplication\Service\ProjectSettingManager;
use SprykerSdk\Sdk\Core\Domain\Entity\SettingInterface;
use SprykerSdk\Sdk\Core\Domain\Repository\SettingRepositoryInterface;
use SprykerSdk\Sdk\Infrastructure\Service\CliValueReceiver;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class InitProjectCommand extends Command
{
    /**
     * @var string
     */
    protected const NAME = 'init:project';

    protected CliValueReceiver $cliValueReceiver;

    protected ProjectSettingManager $projectSettingManager;

    protected SettingRepositoryInterface $settingRepository;

    protected string $projectSettingFileName;

    /**
     * @param \SprykerSdk\Sdk\Infrastructure\Service\CliValueReceiver $cliValueReceiver
     * @param \SprykerSdk\Sdk\Core\Appplication\Service\ProjectSettingManager $projectSettingManager
     * @param \SprykerSdk\Sdk\Core\Domain\Repository\SettingRepositoryInterface $settingRepository
     * @param string $projectSettingFileName
     */
    public function __construct(
        CliValueReceiver $cliValueReceiver,
        ProjectSettingManager $projectSettingManager,
        SettingRepositoryInterface $settingRepository,
        string $projectSettingFileName
    ) {
        $this->projectSettingFileName = $projectSettingFileName;
        $this->settingRepository = $settingRepository;
        $this->projectSettingManager = $projectSettingManager;
        $this->cliValueReceiver = $cliValueReceiver;
        parent::__construct(static::NAME);
    }

    /**
     * @param \Symfony\Component\Console\Input\InputInterface $input
     * @param \Symfony\Component\Console\Output\OutputInterface $output
     *
     * @return int
     */
    public function run(InputInterface $input, OutputInterface $output): int
    {
        $projectSettingPath = getcwd() . '/' . $this->projectSettingFileName;

        if (file_exists($projectSettingPath)) {
            if (!$this->cliValueReceiver->receiveValue('.ssdk file already exists, should it be overwritten? [n]', false, 'bool')) {
                return static::SUCCESS;
            }
        }

        $settingEntities = $this->settingRepository->findProjectSettings();
        $settingEntities = $this->initializeSettingValues($settingEntities);
        $this->writeProjectSettings($settingEntities);

        return static::SUCCESS;
    }

    /**
     * @param array<string, \SprykerSdk\Sdk\Core\Domain\Entity\SettingInterface> $settingEntities
     *
     * @return array<\SprykerSdk\Sdk\Core\Domain\Entity\SettingInterface>
     */
    protected function initializeSettingValues(array $settingEntities): array
    {
        foreach ($settingEntities as $settingEntity) {
            if ($settingEntity->hasInitialization() === false) {
                continue;
            }

            $questionDescription = $settingEntity->getInitializationDescription();

            if (empty($questionDescription)) {
                $questionDescription = 'Initial value for ' . $settingEntity->getPath();
            }

            $values = $this->cliValueReceiver->receiveValue($questionDescription, $settingEntity->getValues(), $settingEntity->getType());

            $values = match ($settingEntity->getType()) {
                'bool' => (bool)$values,
                'array' => (array)$values,
                default => (string)$values,
            };

            if ($settingEntity->getStrategy() === SettingInterface::STRATEGY_MERGE) {
                $values = array_merge($settingEntity->getValues(), $values);
            }

            $settingEntity->setValues($values);
        }

        return $settingEntities;
    }

    /**
     * @param array<int, \SprykerSdk\Sdk\Infrastructure\Entity\Setting> $projectSettings
     *
     * @return void
     */
    protected function writeProjectSettings(array $projectSettings): void
    {
        $projectValues = [];

        foreach ($projectSettings as $projectSetting) {
            $projectValues[$projectSetting->getPath()] = $projectSetting->getValues();
        }

        $this->projectSettingManager->setSettings($projectValues);
    }
}
