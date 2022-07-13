<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerSdk\Sdk\Infrastructure\Event\Telemetry;

use SprykerSdk\Sdk\Core\Appplication\Service\Telemetry\TelemetryEventMetadataFactoryInterface;
use SprykerSdk\Sdk\Core\Appplication\Service\Telemetry\TelemetryEventsSynchronizerInterface;
use SprykerSdk\Sdk\Core\Domain\Entity\TelemetryEvent\Payload\CommandExecutionPayload;
use SprykerSdk\Sdk\Core\Domain\Entity\TelemetryEvent\TelemetryEvent;
use Symfony\Component\Console\Event\ConsoleErrorEvent;
use Symfony\Component\Console\Event\ConsoleTerminateEvent;
use Throwable;

class TelemetryConsoleEventListener
{
    /**
     * @var \SprykerSdk\Sdk\Core\Appplication\Service\Telemetry\TelemetryEventsSynchronizerInterface
     */
    protected TelemetryEventsSynchronizerInterface $telemetryEventsSynchronizer;

    /**
     * @var \SprykerSdk\Sdk\Core\Appplication\Service\Telemetry\TelemetryEventMetadataFactoryInterface
     */
    protected TelemetryEventMetadataFactoryInterface $telemetryEventMetadataFactory;

    /**
     * @var bool
     */
    protected bool $isTelemetryEnabled;

    /**
     * @var \SprykerSdk\Sdk\Infrastructure\Event\Telemetry\TelemetryConsoleEventValidatorInterface
     */
    protected TelemetryConsoleEventValidatorInterface $telemetryConsoleEventValidator;

    /**
     * @param \SprykerSdk\Sdk\Core\Appplication\Service\Telemetry\TelemetryEventsSynchronizerInterface $telemetryEventsSynchronizer
     * @param \SprykerSdk\Sdk\Core\Appplication\Service\Telemetry\TelemetryEventMetadataFactoryInterface $telemetryEventMetadataFactory
     * @param \SprykerSdk\Sdk\Infrastructure\Event\Telemetry\TelemetryConsoleEventValidatorInterface $telemetryConsoleEventValidator
     * @param bool $isTelemetryEnabled
     */
    public function __construct(
        TelemetryEventsSynchronizerInterface $telemetryEventsSynchronizer,
        TelemetryEventMetadataFactoryInterface $telemetryEventMetadataFactory,
        TelemetryConsoleEventValidatorInterface $telemetryConsoleEventValidator,
        bool $isTelemetryEnabled
    ) {
        $this->telemetryEventsSynchronizer = $telemetryEventsSynchronizer;
        $this->telemetryEventMetadataFactory = $telemetryEventMetadataFactory;
        $this->telemetryConsoleEventValidator = $telemetryConsoleEventValidator;
        $this->isTelemetryEnabled = $isTelemetryEnabled;
    }

    /**
     * @param \Symfony\Component\Console\Event\ConsoleTerminateEvent $event
     *
     * @return void
     */
    public function onConsoleTerminate(ConsoleTerminateEvent $event): void
    {
        if (!$this->isTelemetryEnabled || !$this->telemetryConsoleEventValidator->isValid($event)) {
            return;
        }

        $this->addSuccessfulCommandEvent($event);

        $this->synchronizeEvents($event);
    }

    /**
     * @param \Symfony\Component\Console\Event\ConsoleErrorEvent $event
     *
     * @return void
     */
    public function onConsoleError(ConsoleErrorEvent $event): void
    {
        if (!$this->isTelemetryEnabled || !$this->telemetryConsoleEventValidator->isValid($event)) {
            return;
        }

        $this->addFailedCommandEvent($event);
    }

    /**
     * @param \Symfony\Component\Console\Event\ConsoleTerminateEvent $event
     *
     * @return void
     */
    protected function addSuccessfulCommandEvent(ConsoleTerminateEvent $event): void
    {
        $telemetryEvent = new TelemetryEvent(new CommandExecutionPayload(
            (string)($event->getCommand() !== null ? $event->getCommand()->getName() : ''),
            $event->getInput()->getArguments(),
            $event->getInput()->getOptions(),
            '',
            $event->getExitCode(),
        ), $this->telemetryEventMetadataFactory->createTelemetryEventMetadata());

        $this->telemetryEventsSynchronizer->persist($telemetryEvent);
    }

    /**
     * @param \Symfony\Component\Console\Event\ConsoleErrorEvent $event
     *
     * @return void
     */
    protected function addFailedCommandEvent(ConsoleErrorEvent $event): void
    {
        $telemetryEvent = new TelemetryEvent(new CommandExecutionPayload(
            (string)($event->getCommand() !== null ? $event->getCommand()->getName() : ''),
            $event->getInput()->getArguments(),
            $event->getInput()->getOptions(),
            $event->getError()->getMessage(),
            $event->getExitCode(),
        ), $this->telemetryEventMetadataFactory->createTelemetryEventMetadata());

        $this->telemetryEventsSynchronizer->persist($telemetryEvent);
    }

    /**
     * @param \Symfony\Component\Console\Event\ConsoleTerminateEvent $event
     *
     * @return void
     */
    protected function synchronizeEvents(ConsoleTerminateEvent $event): void
    {
        if ($event->getOutput()->isDebug()) {
            $event->getOutput()->writeln('<info>Telemetry events synchronization...</info>');
        }

        try {
            $this->telemetryEventsSynchronizer->synchronize();
        } catch (Throwable $e) {
            $event->getOutput()->writeln(sprintf('<error>%s</error>', $e->getMessage()));
        }

        if ($event->getOutput()->isDebug()) {
            $event->getOutput()->writeln('<info>Telemetry events synchronization finished</info>');
        }
    }
}
