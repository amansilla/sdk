<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerSdk\Sdk\Acceptance\Extension\Tasks;

use PHPUnit\Framework\Assert;
use SprykerSdk\Sdk\Core\Domain\Entity\TelemetryEvent\Payload\CommandExecutionPayload;
use SprykerSdk\Sdk\Infrastructure\Service\Telemetry\ReportTelemetryEventSender;
use SprykerSdk\Sdk\Tests\AcceptanceTester;

class AnalyzerReportTaskCest
{
    /**
     * @var string
     */
    protected const COMMAND = 'analyze:php:code-compliance-report';

    /**
     * @var string
     */
    protected const PROJECT_DIR = 'upgrader_success_project';

    /**
     * @skip incomplete
     *
     * @param \SprykerSdk\Sdk\Tests\AcceptanceTester $I
     *
     * @return void
     */
    public function testAnalyzerReportRunsSuccessfully(AcceptanceTester $I): void
    {
        // Arrange
        $I->cleanReports(static::PROJECT_DIR);

        // Act
        $process = $I->runSdkCommand(
            [static::COMMAND],
            $I->getProjectRoot(static::PROJECT_DIR),
        );

        // Assert
        Assert::assertTrue($process->isSuccessful());

        $I->assertTelemetryEventReport(
            static::COMMAND,
            CommandExecutionPayload::getEventName(),
            $I->getPathFromProjectRoot('reports/' . ReportTelemetryEventSender::REPORT_FILENAME, static::PROJECT_DIR),
        );
    }
}
