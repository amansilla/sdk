<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerSdk\Sdk\Unit\Core\Application\Lifecycle\Event;

use Codeception\Test\Unit;
use SprykerSdk\Sdk\Core\Application\Lifecycle\Event\InitializedEvent;
use SprykerSdk\Sdk\Tests\UnitTester;

/**
 * Auto-generated group annotations
 *
 * @group Sdk
 * @group Unit
 * @group Core
 * @group Application
 * @group Lifecycle
 * @group Event
 * @group InitializedEventTest
 * Add your own group annotations below this line
 */
class InitializedEventTest extends Unit
{
    /**
     * @var \SprykerSdk\Sdk\Tests\UnitTester
     */
    protected UnitTester $tester;

    /**
     * @return void
     */
    public function testGetTaskShouldReturnTask(): void
    {
        // Arrange
        $expectedTask = $this->tester->createTask();
        $event = new InitializedEvent($expectedTask);

        // Act
        $actualTask = $event->getTask();

        // Assert
        $this->assertSame($expectedTask, $actualTask);
    }
}
