<?php

/**
 * Copyright © 2019-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerSdk\Sdk\Presentation\RestApi\Controller\v1;

use SprykerSdk\Sdk\Presentation\RestApi\Processor\SdkUpdateSdkProcessor;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class SdkUpdateSdkController
{
    /**
     * @var \SprykerSdk\Sdk\Presentation\RestApi\Processor\SdkUpdateSdkProcessor
     */
    protected SdkUpdateSdkProcessor $sdkUpdateSdkProcessor;

    /**
     * @param \SprykerSdk\Sdk\Presentation\RestApi\Processor\SdkUpdateSdkProcessor $sdkUpdateSdkProcessor
     */
    public function __construct(SdkUpdateSdkProcessor $sdkUpdateSdkProcessor)
    {
        $this->sdkUpdateSdkProcessor = $sdkUpdateSdkProcessor;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function __invoke(Request $request): Response
    {
        return $this->sdkUpdateSdkProcessor->process($request);
    }
}
