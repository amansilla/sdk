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
    private const NAME = 'Sdk.Visibility.ForbiddenPrivateProperty';

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
		if(!$this->isApplicable($file, $variablePointer)) {
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

    private function isApplicable(File $file, int $variablePointer): bool
    {
        if (!PropertyHelper::isProperty($file, $variablePointer)) {
            return false;
        }

        if ($this->isSniffClass($file, $variablePointer)) {
            return false;
        }

        $suppress = sprintf('%s.%s', self::NAME, self::ERROR_CODE_FORBIDDEN_PRIVATE_PROPERTY);
        if (SuppressHelper::isSniffSuppressed($file, $variablePointer, $suppress)) {
            return false;
        }

        return true;
    }

	private function isSniffClass(File $file, int $position): bool
	{
		$classTokenPosition = ClassHelper::getClassPointer($file, $position);
		$classNameToken = ClassHelper::getName($file, $classTokenPosition);

		return StringHelper::endsWith($classNameToken, 'Sniff');
	}

	/**
	 * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint.DisallowedMixedTypeHint
     *
     * @param File $file
     * @param int $position
     *
     * @return array<mixed>
	 */
	private function getPropertyScopeModifier(File $file, int $position): array
	{
        $scopeModifierPosition = TokenHelper::findPrevious($file, Tokens::$scopeModifiers, $position - 1);

        $tokens = $file->getTokens();

        return $tokens[$scopeModifierPosition];
	}
}
