<?php declare(strict_types = 1);

namespace Sdk\Sniffs\Visibility;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use SlevomatCodingStandard\Helpers\ClassHelper;
use SlevomatCodingStandard\Helpers\FunctionHelper;
use SlevomatCodingStandard\Helpers\StringHelper;
use SlevomatCodingStandard\Helpers\SuppressHelper;
use SlevomatCodingStandard\Helpers\TokenHelper;
use const T_FUNCTION;

final class ForbiddenPrivateMethodSniff implements Sniff
{
    private const CODE_FORBIDDEN_PRIVATE_METHOD = 'ForbiddenPrivateMethod';
    private const ERROR_MESSAGE_FORBIDDEN_PRIVATE_METHOD = 'Private methods are forbidden by Spryker to keep code extendable.';
    private const NAME = 'Sdk.Visibility.ForbiddenPrivateMethod';

	/**
	 * @return array<int, (int|string)>
	 */
	public function register(): array
	{
		return [T_FUNCTION];
	}

    /**
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.ParameterTypeHint.MissingNativeTypeHint
     *
     * @param File $file
     * @param $methodPointer
     *
     * @return void
     */
	public function process(File $file, $methodPointer): void
	{
        if (!$this->isApplicable($file, $methodPointer)) {
            return;
        }

		$scopeModifierToken = $this->getMethodScopeModifier($file, $methodPointer);
		if ($scopeModifierToken['code'] !== T_PRIVATE) {
			return;
		}

        $file->addError(
            static::ERROR_MESSAGE_FORBIDDEN_PRIVATE_METHOD,
            $methodPointer,
            self::CODE_FORBIDDEN_PRIVATE_METHOD
        );
	}

    private function isApplicable(File $file, int $methodPointer): bool
    {
        if (!FunctionHelper::isMethod($file, $methodPointer)) {
            return false;
        }

        if ($this->isSniffClass($file, $methodPointer)) {
            return false;
        }

        $suppress = sprintf('%s.%s', self::NAME, self::CODE_FORBIDDEN_PRIVATE_METHOD);
        if (SuppressHelper::isSniffSuppressed($file, $methodPointer, $suppress)) {
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
	private function getMethodScopeModifier(File $file, int $position): array
	{
		$scopeModifierPosition = TokenHelper::findPrevious($file, Tokens::$scopeModifiers, $position - 1);
        $token = $file->getTokens();

        return $token[$scopeModifierPosition];
	}
}
