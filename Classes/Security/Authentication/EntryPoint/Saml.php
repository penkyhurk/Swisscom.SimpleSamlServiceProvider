<?php
namespace Swisscom\SimpleSamlServiceProvider\Security\Authentication\EntryPoint;

/*
 * This file is part of the Swisscom.SimpleSamlServiceProvider package.
 */

use SimpleSAML\Auth\Simple;
use Swisscom\SimpleSamlServiceProvider\Exception;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Neos\Flow\Security\Authentication\EntryPoint\AbstractEntryPoint;
use Neos\Flow\Annotations as Flow;


class Saml extends AbstractEntryPoint
{

    /**
     * @Flow\InjectConfiguration
     * @var array
     */
    protected $settings;

    /**
     * @var \Swisscom\SimpleSamlServiceProvider\Authentication\AuthenticationInterface
     * @Flow\Inject
     */
    protected $authenticationInterface;

    /**
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @return ResponseInterface
     * t h r o w s Exception
     */
    public function startAuthentication(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Simple $authentication */
        $authentication = $this->authenticationInterface;
        if ($authentication === null) {
            // old: return;
            $response->setStatus(401)
            $response->setContent( json_encode( [ 'statusCode' => 401, 'statusMessage' => 'undefined authentication interface' ] ) );
            $response->send();
            exit;
        }

        if ($authentication->isAuthenticated()) {
            $authentication->logout();
            // Should automatically be authenticated by the SamlProvider, but something went wrong.
            throw new Exception('User is authenticated by the identity provider, but not able to be authenticated by system.', 1516117713);
        } else {
            $params = $this->settings['loginParams'];
            $options = $this->getOptions();
            if (isset($options['loginParams'])) {
                $params = array_merge($params, $options['loginParams']);
            }
            $authentication->requireAuth($params);
        }
    }
}
