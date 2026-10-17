<?php declare(strict_types=1);

namespace Alantiller\Permission\Exceptions;

use RuntimeException;
use Throwable;

/** Base class for permission-library faults; ordinary access denial returns false. */
class BaseException extends RuntimeException
{
    /** @var string Stable identifier overridden by each exception category. */
    protected const ERROR_CODE = 'permission_error';

    /** @var string Machine-readable failure category. */
    public readonly string $error_code;

    /**
     * Describe a library failure without including user context or SQL values.
     *
     * @param string $message Diagnostic text intended for trusted application code.
     * @param int $code Native numeric exception code.
     * @param Throwable|null $previous Underlying cause, which may contain sensitive database details.
     */
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->error_code = static::ERROR_CODE;
    }
}
