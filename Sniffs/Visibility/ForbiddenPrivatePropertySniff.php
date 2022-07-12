<?php declare(strict_types = 1);

namespace Sdk\Sniffs\Visibility;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use SlevomatCodingStandard\Helpers\ClassHelper;
use SlevomatCodingStandard\Helpers\PropertyHelper;
use SlevomatCodingStandard\Helpers\StringHelper;
use SlevomatCodingStandard\Helpers\SuppressHelper;
use SlevomatCodingStandard\Helpers\TokenHelper;
use const T_VARIABLE;

final class ForbiddenPrivatePropertySniff implements Sniff
{
    private const ERROR_CODE_FORBIDDEN_PRIVATE_PROPERTY = 'ForbiddenPrivateProperty';
    private const ERROR_MESSAGE_FORBIDDEN_PRIVATE_PROPERTY = 'Private properties usage is forbidden by Spryker due to extendability reasons.';

	/**
	 * @return array<int, (int|string)>
	 */
	public function register(): array
	{
		return [T_VARIABLE];
	}

	/**
	 * @phpcsSuppress SlevomatCodingStandard.TypeHints.ParameterTypeHint.MissingNativeTypeHint
     *
     * @param File $file
     * @param int $variablePointer
	 */
	public function process(File $file, $variablePointer): void
	{
		if(!$this->isPrivate($file, $variablePointer)) {
            return;
        }

        if (!PropertyHelper::isProperty($file, $variablePointer)) {
            return;
        }

		$scopeModifierToken = $this->getPropertyScopeModifier($file, $variablePointer);
		if ($scopeModifierToken['code'] !== T_PRIVATE) {
			return;
		}

		$file->addError(
            static::ERROR_MESSAGE_FORBIDDEN_PRIVATE_PROPERTY,
            $variablePointer,
            self::ERROR_CODE_FORBIDDEN_PRIVATE_PROPERTY
        );
	}

    private function isPrivate(File $phpCsFile, int $stackPointer): bool
    {
        return (bool)$phpCsFile->findFirstOnLine(T_PRIVATE, $stackPointer);
    }

	private function getPropertyScopeModifier(File $file, int $position): ?array
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
