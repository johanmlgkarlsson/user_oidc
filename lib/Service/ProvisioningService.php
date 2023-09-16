<?php

namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\Db\ProviderMapper;
use OCA\UserOIDC\Db\UserMapper;
use OCA\UserOIDC\Event\AttributeMappedEvent;
use OCP\DB\Exception;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClientService;
use OCP\IGroupManager;
use OCP\ILogger;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\ICrypto;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use OCP\User\Events\UserChangedEvent;

class ProvisioningService {
	/** @var UserMapper */
	private $userMapper;

	/** @var LocalIdService */
	private $idService;

	/** @var IUserManager */
	private $userManager;

	/** @var IGroupManager */
	private $groupManager;

	/** @var IEventDispatcher */
	private $eventDispatcher;

	/** @var ILogger */
	private $logger;

	/** @var ICrypto */
	private $crypto;

	/** @var IClientService */
	private $clientService;

	/** @var ProviderService */
	private $providerService;

	/** @var ProviderMapper */
	private $providerMapper;

	public function __construct(
		LocalIdService   $idService,
		ProviderService  $providerService,
		ProviderMapper   $providerMapper,
		UserMapper       $userMapper,
		IUserManager     $userManager,
		IGroupManager    $groupManager,
		IEventDispatcher $eventDispatcher,
		ICrypto          $crypto,
		IClientService   $clientService,
		ILogger          $logger
	) {
		$this->idService = $idService;
		$this->providerService = $providerService;
		$this->providerMapper = $providerMapper;
		$this->userMapper = $userMapper;
		$this->userManager = $userManager;
		$this->groupManager = $groupManager;
		$this->eventDispatcher = $eventDispatcher;
		$this->logger = $logger;
		$this->crypto = $crypto;
		$this->clientService = $clientService;
	}

	/**
	 * @param string $tokenUserId
	 * @param int $providerId
	 * @param object $idTokenPayload
	 * @return IUser|null
	 * @throws Exception
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	public function provisionUser(string $tokenUserId, int $providerId, object $idTokenPayload): ?IUser {
		// get name/email/quota information from the token itself
		$emailAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_EMAIL, 'email');
		$email = $idTokenPayload->{$emailAttribute} ?? null;
		$displaynameAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_DISPLAYNAME, 'name');
		$userName = $idTokenPayload->{$displaynameAttribute} ?? null;
		$quotaAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_QUOTA, 'quota');
		$quota = $idTokenPayload->{$quotaAttribute} ?? null;

		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_UID, $idTokenPayload, $tokenUserId);
		$this->eventDispatcher->dispatchTyped($event);

		$backendUser = $this->userMapper->getOrCreate($providerId, $event->getValue());
		$this->logger->debug('User obtained from the OIDC user backend: ' . $backendUser->getUserId());

		$user = $this->userManager->get($backendUser->getUserId());
		if ($user === null) {
			return null;
		}

		// Update displayname
		if (isset($userName)) {
			$newDisplayName = mb_substr($userName, 0, 255);
			$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $idTokenPayload, $newDisplayName);
		} else {
			$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_DISPLAYNAME, $idTokenPayload);
		}
		$this->eventDispatcher->dispatchTyped($event);
		$this->logger->debug('Displayname mapping event dispatched');
		if ($event->hasValue()) {
			$oldDisplayName = $backendUser->getDisplayName();
			$newDisplayName = $event->getValue();
			if ($newDisplayName !== $oldDisplayName) {
				$backendUser->setDisplayName($newDisplayName);
				$this->userMapper->update($backendUser);
			}
			// 2 reasons why we should update the display name: It does not match the one
			// - of our backend
			// - returned by the user manager (outdated one before the fix in https://github.com/nextcloud/user_oidc/pull/530)
			if ($newDisplayName !== $oldDisplayName || $newDisplayName !== $user->getDisplayName()) {
				$this->eventDispatcher->dispatchTyped(new UserChangedEvent($user, 'displayName', $newDisplayName, $oldDisplayName));
			}
		}

		// Update e-mail
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_EMAIL, $idTokenPayload, $email);
		$this->eventDispatcher->dispatchTyped($event);
		$this->logger->debug('Email mapping event dispatched');
		if ($event->hasValue()) {
			$user->setEMailAddress($event->getValue());
		}

		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_QUOTA, $idTokenPayload, $quota);
		$this->eventDispatcher->dispatchTyped($event);
		$this->logger->debug('Quota mapping event dispatched');
		if ($event->hasValue()) {
			$user->setQuota($event->getValue());
		}

		// Update groups
		if ($this->providerService->getSetting($providerId, ProviderService::SETTING_GROUP_PROVISIONING, '0') === '1') {
			$this->provisionUserGroups($user, $providerId, $idTokenPayload);
		}

		return $user;
	}

	public function provisionUserGroups(IUser $user, int $providerId, object $idTokenPayload): void {
		$groupsAttribute = $this->providerService->getSetting($providerId, ProviderService::SETTING_MAPPING_GROUPS, 'groups');
		$groupsData = $idTokenPayload->{$groupsAttribute} ?? null;
		$event = new AttributeMappedEvent(ProviderService::SETTING_MAPPING_GROUPS, $idTokenPayload, json_encode($groupsData));
		$this->eventDispatcher->dispatchTyped($event);
		$this->logger->debug('Group mapping event dispatched');
		if ($event->hasValue() && $event->getValue() !== null) {
			$groups = json_decode($event->getValue());
			$userGroups = $this->groupManager->getUserGroups($user);
			$syncGroups = [];

			$token = null;
			$tenant = null;
			if ($this->providerService->getSetting($providerId, ProviderService::SETTING_AZURE_GROUP_NAMES, '0') === '1') {
				$url = $this->providerMapper->getProvider($providerId)->getDiscoveryEndpoint();
				$tenant = explode('//', $url);
				$tenant = count($tenant) === 1 ? $tenant[0] : $tenant[1];
				$tenant = explode('/', $tenant);
				if (count($tenant) === 1) {
					$this->logger->error('Could not figure out the tenant id. (Is the discovery endpoint formatted properly?) Will not sync groups');
					return;
				}
				$tenant = $tenant[1];

				$client = $this->clientService->newClient();
				try {
					$response = $client->post("https://login.microsoftonline.com/$tenant/oauth2/v2.0/token", [
						'headers' => [ 'Accept' => 'application/json' ],
						'form_params' => [
							'client_id' => $this->providerMapper->getProvider($providerId)->getClientId(),
							'scope' => 'https://graph.microsoft.com/.default',
							'client_secret' => $this->crypto->decrypt($this->providerMapper->getProvider($providerId)->getClientSecret()),
							'grant_type' => 'client_credentials'
						],
						'http_errors' => false
					]);
				} catch (\Exception $e) {
					$this->logger->error($e->getMessage());
					return;
				}

				$res = $response->getBody();
				if (!is_string($res)) {
					$this->logger->error('Could not fetch Bearer token for Microsoft Graph. Will not sync groups');
					return;
				}
				$res = json_decode($res, true);
				if (empty($res)) {
					$this->logger->error('Could not fetch Bearer token for Microsoft Graph. Will not sync groups');
					return;
				}
				$token = $res['access_token'];
			}

			foreach ($groups as $k => $v) {
				if (is_object($v)) {
					// Handle array of objects, e.g. [{gid: "1", displayName: "group1"}, ...]
					if (empty($v->gid) && $v->gid !== '0' && $v->gid !== 0) {
						continue;
					}
					$group = $v;
				} elseif (is_string($v)) {
					// Handle array of strings, e.g. ["group1", "group2", ...]
					$group = (object)['gid' => $v];
				} else {
					continue;
				}
				if ($this->providerService->getSetting($providerId, ProviderService::SETTING_AZURE_GROUP_NAMES, '0') === '1' && is_string($v)) {
					$client = $this->clientService->newClient();
					try {
						$response = $client->get(
							"https://graph.microsoft.com/v1.0/$tenant/groups/" . $v,
							[ 'headers' => [ 'Accept' => 'application/json', 'Authorization' => "Bearer $token" ], 'http_errors' => false ]
						);
					} catch (\Exception $e) {
						$this->logger->error($e->getMessage());
						continue;
					}
					$res = $response->getBody();

					if (!is_string($res)) {
						$this->logger->error('No response from Microsoft Graph while fetching group name. Will not sync the group ' . $v);
						continue;
					}
					$res = json_decode($res, true); // https://learn.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0&tabs=http#response-1

					if (isset($res['error'])) {
						$errorMessage = !empty($res['error']['message']) && is_string($res['error']['message']) ? $res['error']['message'] : '';
						$this->logger->error('Error response from Microsoft Graph while fetching group name. Will not sync the group ' . $v . '. Graph said: ' . $errorMessage);
						continue;
					}

					if (empty($res['displayName'])) {
						$this->logger->error('Empty response from Microsoft Graph while fetching group name. Will not sync the group ' . $v);
						continue;
					}
					$group = (object)['gid' => $res['displayName']];

					if ($this->providerService->getSetting($providerId, ProviderService::SETTING_PROVIDER_BASED_ID, '0') === '1') {
						$providerName = $this->providerMapper->getProvider($providerId)->getIdentifier();
						$group->gid = $providerName . '-' . $group->gid;
					}
					if (strlen($group->gid) > 64) {
						$this->logger->warning('Group id ' . $group->gid . ' longer than supported. Group id truncated.');
						$group->displayName = $group->gid;
						$group->gid = substr($group->gid, 0, 64);
						if (strlen($group->displayName) > 255) {
							$this->logger->warning('Group name ' . $group->displayName . ' longer than supported. Group name truncated.');
							$group->displayName = substr($group->displayName, 0, 255);
						}
					}
				} else {
					$group->gid = $this->idService->getId($providerId, $group->gid);
				}
				$syncGroups[] = $group;
			}

			foreach ($userGroups as $group) {
				if (!in_array($group->getGID(), array_column($syncGroups, 'gid'))) {
					$group->removeUser($user);
				}
			}

			foreach ($syncGroups as $group) {
				// Creates a new group or return the exiting one.
				if ($newGroup = $this->groupManager->createGroup($group->gid)) {
					// Adds the user to the group. Does nothing if user is already in the group.
					$newGroup->addUser($user);

					if (isset($group->displayName)) {
						$newGroup->setDisplayName($group->displayName);
					}
				}
			}
		}
	}
}
