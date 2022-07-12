<?php declare(strict_types = 1);

namespace Sdk\Sniffs\Visibility;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Util\Tokens;
use Spryker\Sniffs\AbstractSniffs\AbstractSprykerSniff;
use const T_FUNCTION;

final class ForbiddenPrivateMethodSniff extends AbstractSprykerSniff
{
    private const CODE_FORBIDDEN_PRIVATE_METHOD = 'ForbiddenPrivateMethod';
    private const ERROR_MESSAGE_FORBIDDEN_PRIVATE_METHOD = 'Private methods are forbidden by Spryker to keep code extendable.';

	public function register(): array
	{
		return [T_FUNCTION];
	}

    /**
     * @param File $file
     * @param int $methodPointer
     *
     * @return void
     */
	public function process(File $file, $methodPointer): void
	{
        if (!$this->isPrivate($file, $methodPointer)) {
            return;
        }

		$scopeModifierToken = $this->getMethodScopeModifier($file, $methodPointer);
		if (!$scopeModifierToken || $scopeModifierToken['code'] !== T_PRIVATE) {
			return;
		}

        $file->addError(
            self::ERROR_MESSAGE_FORBIDDEN_PRIVATE_METHOD,
            $methodPointer,
            self::CODE_FORBIDDEN_PRIVATE_METHOD
        );
	}

    private function isPrivate(File $phpCsFile, int $stackPointer): bool
    {
        return (bool)$phpCsFile->findFirstOnLine(T_PRIVATE, $stackPointer);
    }

    private function getMethodScopeModifier(File $file, int $position): ?array
    {
        $scopeModifierPosition = $this->findPreviousPosition($file, $position);

        $tokens = $file->getTokens();

        return $scopeModifierPosition ? $tokens[$scopeModifierPosition] : null;
	}

    private function findPreviousPosition(File $file, int $position): ?int
    {
        $token = $file->findPrevious(Tokens::$scopeModifiers, $position - 1);

        return $token !== false ? $token : null;
    }
}
