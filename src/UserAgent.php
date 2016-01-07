<?php
namespace Dopesong\Middleware;

use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Class UserAgent
 * @package Dopesong\Middleware
 */
class UserAgent
{
    /**
     * Enable checking of proxy headers (X-User-Agent to determined client User agent.
     *
     * Defaults to false as only $_SERVER['HTTP_USER_AGENT'] is a trustworthy source
     * of IP address.
     *
     * @var bool
     */
    protected $checkProxyHeaders;

    /**
     * List of trusted proxy IP addresses
     *
     * If not empty, then one of these IP addresses must be in $_SERVER['HTTP_USER_AGENT']
     * in order for the proxy headers to be looked at.
     *
     * @var array
     */
    protected $trustedProxies;

    /**
     * Name of the attribute added to the ServerRequest object
     *
     * @var string
     */
    protected $attributeName = 'user_agent';

    /**
     * List of proxy headers inspected for the client user agent
     *
     * @var array
     */
    protected $headersToInspect = [
        'X-User-Agent',
    ];

    /**
     * Constructor
     *
     * @param bool $checkProxyHeaders Whether to use proxy headers to determine client user agent
     * @param array $trustedProxies   List of IP addresses of trusted proxies
     * @param string $attributeName   Name of attribute added to ServerRequest object
     * @param array $headersToInspect List of headers to inspect
     */
    public function __construct(
        $checkProxyHeaders = false,
        array $trustedProxies = [],
        $attributeName = null,
        array $headersToInspect = []
    ) {
        $this->checkProxyHeaders = $checkProxyHeaders;
        $this->trustedProxies = $trustedProxies;

        if ($attributeName) {
            $this->attributeName = $attributeName;
        }
        if (!empty($headersToInspect)) {
            $this->headersToInspect = $headersToInspect;
        }
    }

    /**
     * Set the "$attributeName" attribute to the client's user agent as determined from
     * the proxy header (X-User-Agent or from $_SERVER['HTTP_USER_AGENT']
     *
     * @param ServerRequestInterface $request PSR7 request
     * @param ResponseInterface $response     PSR7 response
     * @param callable $next                  Next middleware
     *
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        if (!$next) {
            return $response;
        }

        $ipAddress = $this->determineClientUserAgent($request);
        $request = $request->withAttribute($this->attributeName, $ipAddress);

        return $response = $next($request, $response);
    }

    /**
     * Find out the client's user agent from the headers available to us
     *
     * @param  ServerRequestInterface $request PSR-7 Request
     * @return string
     */
    protected function determineClientUserAgent($request)
    {
        $userAgent = null;

        $serverParams = $request->getServerParams();
        $userAgent = $serverParams['HTTP_USER_AGENT'];

        $checkProxyHeaders = $this->checkProxyHeaders;
        if ($checkProxyHeaders && !empty($this->trustedProxies)) {
            if (!in_array($userAgent, $this->trustedProxies)) {
                $checkProxyHeaders = false;
            }
        }

        if ($checkProxyHeaders) {
            foreach ($this->headersToInspect as $header) {
                if ($request->hasHeader($header)) {
                    $userAgent = trim(current(explode(',', $request->getHeaderLine($header))));
                    break;
                }
            }
        }

        return $userAgent;
    }
}
