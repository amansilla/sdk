<?php

namespace SprykerSdk\Sdk\Presentation\Web\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class SprykerSdkWebExtension extends Extension
{
    /**
     * @param array $configs
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     *
     * @return void
     */
    public function load(array $configs, ContainerBuilder $container): void
    {
        (new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config')))->load('services.yaml');
    }
}
