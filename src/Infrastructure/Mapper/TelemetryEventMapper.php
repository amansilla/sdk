<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerSdk\Sdk\Infrastructure\Mapper;

use SprykerSdk\Sdk\Core\Domain\Entity\TelemetryEvent\TelemetryEvent as DomainTelemetryEvent;
use SprykerSdk\Sdk\Infrastructure\Entity\TelemetryEvent as InfrastructureTelemetryEvent;
use SprykerSdk\SdkContracts\Entity\Telemetry\TelemetryEventInterface;

class TelemetryEventMapper implements TelemetryEventMapperInterface
{
    /**
     * @param \SprykerSdk\SdkContracts\Entity\Telemetry\TelemetryEventInterface $telemetryEvent
     *
     * @return \SprykerSdk\Sdk\Infrastructure\Entity\TelemetryEvent
     */
    public function mapToInfrastructureTelemetryEvent(TelemetryEventInterface $telemetryEvent): InfrastructureTelemetryEvent
    {
        $infrastructureTelemetryEvent = new InfrastructureTelemetryEvent($telemetryEvent->getPayload());

        $this->mapTelemetryEvents($telemetryEvent, $infrastructureTelemetryEvent);

        return $infrastructureTelemetryEvent;
    }

    /**
     * @param \SprykerSdk\SdkContracts\Entity\Telemetry\TelemetryEventInterface $telemetryEvent
     *
     * @return \SprykerSdk\Sdk\Core\Domain\Entity\TelemetryEvent\TelemetryEvent
     */
    public function mapToDomainTelemetryEvent(TelemetryEventInterface $telemetryEvent): DomainTelemetryEvent
    {
        $domainTelemetryEvent = new DomainTelemetryEvent($telemetryEvent->getPayload());

        $this->mapTelemetryEvents($telemetryEvent, $domainTelemetryEvent);

        return $domainTelemetryEvent;
    }

    /**
     * @param \SprykerSdk\SdkContracts\Entity\Telemetry\TelemetryEventInterface $fromTelemetryEvent
     * @param \SprykerSdk\Sdk\Infrastructure\Entity\TelemetryEvent|\SprykerSdk\Sdk\Core\Domain\Entity\TelemetryEvent\TelemetryEvent $toTelemetryEvent
     *
     * @return void
     */
    public function mapTelemetryEvents(TelemetryEventInterface $fromTelemetryEvent, TelemetryEventInterface $toTelemetryEvent): void
    {
        $toTelemetryEvent->setId($fromTelemetryEvent->getId());
        $toTelemetryEvent->setName($fromTelemetryEvent->getName());
        $toTelemetryEvent->setCreatedAt($fromTelemetryEvent->getCreatedAt());
        $toTelemetryEvent->setPayload($fromTelemetryEvent->getPayload());
        $toTelemetryEvent->setSynchronizationAttemptsCount($fromTelemetryEvent->getSynchronizationAttemptsCount());
        $toTelemetryEvent->setLastSynchronisationTimestamp($fromTelemetryEvent->getLastSynchronisationTimestamp());
        $toTelemetryEvent->setVersion($fromTelemetryEvent->getVersion());
    }
}
