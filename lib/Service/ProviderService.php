<?php
/*
 * @copyright Copyright (c) 2021 Julius Härtl <jus@bitgrid.net>
 *
 * @author Julius Härtl <jus@bitgrid.net>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

declare(strict_types=1);


namespace OCA\UserOIDC\Service;

use OCA\UserOIDC\AppInfo\Application;
use OCA\UserOIDC\Db\Provider;
use OCA\UserOIDC\Db\ProviderMapper;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IConfig;

class ProviderService {
	public const SETTING_CHECK_BEARER = 'checkBearer';
	public const SETTING_SEND_ID_TOKEN_HINT = 'sendIdTokenHint';
	public const SETTING_BEARER_PROVISIONING = 'bearerProvisioning';
	public const SETTING_UNIQUE_UID = 'uniqueUid';
	public const SETTING_MAPPING_UID = 'mappingUid';
	public const SETTING_MAPPING_UID_DEFAULT = 'sub';
	public const SETTING_MAPPING_DISPLAYNAME = 'mappingDisplayName';
	public const SETTING_MAPPING_EMAIL = 'mappingEmail';
	public const SETTING_MAPPING_QUOTA = 'mappingQuota';
	public const SETTING_MAPPING_GROUPS = 'mappingGroups';
	public const SETTING_MAPPING_ADDRESS = 'mappingAddress';
	public const SETTING_MAPPING_STREETADDRESS = 'mappingStreetaddress';
	public const SETTING_MAPPING_POSTALCODE = 'mappingPostalcode';
	public const SETTING_MAPPING_LOCALITY = 'mappingLocality';
	public const SETTING_MAPPING_REGION = 'mappingRegion';
	public const SETTING_MAPPING_COUNTRY = 'mappingCountry';
	public const SETTING_MAPPING_WEBSITE = 'mappingWebsite';
	public const SETTING_MAPPING_AVATAR = 'mappingAvatar';
	public const SETTING_MAPPING_TWITTER = 'mappingTwitter';
	public const SETTING_MAPPING_FEDIVERSE = 'mappingFediverse';
	public const SETTING_MAPPING_ORGANISATION = 'mappingOrganisation';
	public const SETTING_MAPPING_ROLE = 'mappingRole';
	public const SETTING_MAPPING_HEADLINE = 'mappingHeadline';
	public const SETTING_MAPPING_BIOGRAPHY = 'mappingBiography';
	public const SETTING_MAPPING_PHONE = 'mappingPhonenumber';
	public const SETTING_MAPPING_GENDER = 'mappingGender';
	public const SETTING_EXTRA_CLAIMS = 'extraClaims';
	public const SETTING_JWKS_CACHE = 'jwksCache';
	public const SETTING_JWKS_CACHE_TIMESTAMP = 'jwksCacheTimestamp';
	public const SETTING_PROVIDER_BASED_ID = 'providerBasedId';
	public const SETTING_GROUP_PROVISIONING = 'groupProvisioning';
	public const SETTING_AZURE_GROUP_NAMES = 'azureGroupNames';

	private const BOOLEAN_SETTINGS = array(
		self::SETTING_GROUP_PROVISIONING,
		self::SETTING_PROVIDER_BASED_ID,
		self::SETTING_BEARER_PROVISIONING,
		self::SETTING_UNIQUE_UID,
		self::SETTING_CHECK_BEARER,
		self::SETTING_SEND_ID_TOKEN_HINT,
		self::SETTING_AZURE_GROUP_NAMES,
	);


	/** @var IConfig */
	private $config;
	/** @var ProviderMapper */
	private $providerMapper;

	public function __construct(IConfig $config, ProviderMapper $providerMapper) {
		$this->config = $config;
		$this->providerMapper = $providerMapper;
	}

	public function getProvidersWithSettings(): array {
		$providers = $this->providerMapper->getProviders();
		return array_map(function ($provider) {
			$providerSettings = $this->getSettings($provider->getId());
			return array_merge($provider->jsonSerialize(), ['settings' => $providerSettings]);
		}, $providers);
	}

	public function getProviderByIdentifier(string $identifier): ?Provider {
		try {
			return $this->providerMapper->findProviderByIdentifier($identifier);
		} catch (DoesNotExistException $e) {
			return null;
		}
	}

	public function getProviderWithSettings(int $id): array {
		$provider = $this->providerMapper->getProvider($id);
		$providerSettings = $this->getSettings($provider->getId());
		return array_merge($provider->jsonSerialize(), ['settings' => $providerSettings]);
	}

	public function getSettings(int $providerId): array {
		$result = [];
		foreach ($this->getSupportedSettings() as $setting) {
			$value = $this->getSetting($providerId, $setting);
			$result[$setting] = $this->convertToJSON($setting, $value);
		}
		return $result;
	}

	public function setSettings(int $providerId, array $settings): array {
		$storedSettings = $this->getSettings($providerId);
		foreach ($settings as $setting => $value) {
			if (!in_array($setting, $this->getSupportedSettings(), true)) {
				continue;
			}
			$this->setSetting($providerId, $setting, $this->convertFromJSON($setting, $value));
			$storedSettings[$setting] = $value;
		}
		return $storedSettings;
	}

	public function deleteSettings(int $providerId): void {
		foreach ($this->getSupportedSettings() as $setting) {
			$this->config->deleteAppValue(Application::APP_ID, $this->getSettingsKey($providerId, $setting));
		}
	}

	public function setSetting(int $providerId, string $key, string $value): void {
		$this->config->setAppValue(Application::APP_ID, $this->getSettingsKey($providerId, $key), $value);
	}

	public function getSetting(int $providerId, string $key, string $default = ''): string {
		$value = $this->config->getAppValue(Application::APP_ID, $this->getSettingsKey($providerId, $key), '');
		if ($value === '') {
			return $default;
		}
		return $value;
	}

	private function getSettingsKey(int $providerId, string $key): string {
		return 'provider-' . $providerId . '-' . $key;
	}

	private function getSupportedSettings(): array {
		return [
			self::SETTING_MAPPING_DISPLAYNAME,
			self::SETTING_MAPPING_EMAIL,
			self::SETTING_MAPPING_QUOTA,
			self::SETTING_MAPPING_UID,
			self::SETTING_MAPPING_GROUPS,
			self::SETTING_MAPPING_ADDRESS,
			self::SETTING_MAPPING_STREETADDRESS,
			self::SETTING_MAPPING_POSTALCODE,
			self::SETTING_MAPPING_LOCALITY,
			self::SETTING_MAPPING_REGION,
			self::SETTING_MAPPING_COUNTRY,
			self::SETTING_MAPPING_WEBSITE,
			self::SETTING_MAPPING_AVATAR,
			self::SETTING_MAPPING_TWITTER,
			self::SETTING_MAPPING_FEDIVERSE,
			self::SETTING_MAPPING_ORGANISATION,
			self::SETTING_MAPPING_ROLE,
			self::SETTING_MAPPING_HEADLINE,
			self::SETTING_MAPPING_BIOGRAPHY,
			self::SETTING_MAPPING_PHONE,
			self::SETTING_MAPPING_GENDER,
			self::SETTING_UNIQUE_UID,
			self::SETTING_CHECK_BEARER,
			self::SETTING_SEND_ID_TOKEN_HINT,
			self::SETTING_BEARER_PROVISIONING,
			self::SETTING_EXTRA_CLAIMS,
			self::SETTING_PROVIDER_BASED_ID,
			self::SETTING_GROUP_PROVISIONING,
			self::SETTING_AZURE_GROUP_NAMES
		];
	}

	private function convertFromJSON(string $key, $value): string {
		if (in_array($key, self::BOOLEAN_SETTINGS)) {
			$value = $value ? '1' : '0';
		}
		return (string)$value;
	}

	private function convertToJSON(string $key, $value) {
		// default is disabled (if not set)
		if (in_array($key, self::BOOLEAN_SETTINGS)) {
			return $value === '1';
		}
		return (string)$value;
	}
}
