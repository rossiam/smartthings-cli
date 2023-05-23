const shared = require('../../.eslintrc.js')

shared.parserOptions.tsconfigRootDir = __dirname
shared.ignorePatterns = [
	'src/__tests__/commands/apps.test.ts',
	'src/__tests__/commands/apps/authorize.test.ts',
	'src/__tests__/commands/apps/create.test.ts',
	'src/__tests__/commands/apps/delete.test.ts',
	'src/__tests__/commands/apps/oauth.test.ts',
	'src/__tests__/commands/apps/oauth/generate.test.ts',
	'src/__tests__/commands/apps/oauth/update.test.ts',
	'src/__tests__/commands/apps/register.test.ts',
	'src/__tests__/commands/apps/settings.test.ts',
	'src/__tests__/commands/apps/settings/update.test.ts',
	'src/__tests__/commands/apps/update.test.ts',
	'src/__tests__/commands/capabilities/translations.test.ts',
	'src/__tests__/commands/config/reset.test.ts',
	'src/__tests__/commands/devicepreferences/translations.test.ts',
	'src/__tests__/commands/devicepreferences/translations/create.test.ts',
	'src/__tests__/commands/devicepreferences/translations/update.test.ts',
	'src/__tests__/commands/deviceprofiles.test.ts',
	'src/__tests__/commands/devices.test.ts',
	'src/__tests__/commands/devices/capability-status.test.ts',
	'src/__tests__/commands/devices/commands.test.ts',
	'src/__tests__/commands/devices/delete.test.ts',
	'src/__tests__/commands/devices/history.test.ts',
	'src/__tests__/commands/devices/update.test.ts',
	'src/__tests__/commands/installedapps.test.ts',
	'src/__tests__/commands/installedapps/delete.test.ts',
	'src/__tests__/commands/installedapps/rename.test.ts',
	'src/__tests__/commands/installedschema.test.ts',
	'src/__tests__/commands/locations.test.ts',
	'src/__tests__/commands/locations/create.test.ts',
	'src/__tests__/commands/locations/delete.test.ts',
	'src/__tests__/commands/locations/history.test.ts',
	'src/__tests__/commands/locations/rooms.test.ts',
	'src/__tests__/commands/locations/rooms/create.test.ts',
	'src/__tests__/commands/locations/rooms/delete.test.ts',
	'src/__tests__/commands/locations/rooms/update.test.ts',
	'src/__tests__/commands/locations/update.test.ts',
	'src/__tests__/commands/organizations.test.ts',
	'src/__tests__/commands/presentation/device-config.test.ts',
	'src/__tests__/commands/rules.test.ts',
	'src/__tests__/commands/rules/create.test.ts',
	'src/__tests__/commands/rules/delete.test.ts',
	'src/__tests__/commands/rules/execute.test.ts',
	'src/__tests__/commands/rules/update.test.ts',
	'src/__tests__/commands/scenes.test.ts',
	'src/__tests__/commands/scenes/execute.test.ts',
	'src/__tests__/commands/schema.test.ts',
	'src/__tests__/commands/schema/authorize.test.ts',
	'src/__tests__/commands/schema/create.test.ts',
	'src/__tests__/commands/schema/delete.test.ts',
	'src/__tests__/commands/schema/regenerate.test.ts',
	'src/__tests__/commands/schema/update.test.ts',
	'src/__tests__/commands/virtualdevices.test.ts',
	'src/__tests__/commands/virtualdevices/create-standard.test.ts',
	'src/__tests__/commands/virtualdevices/create.test.ts',
	'src/__tests__/commands/virtualdevices/delete.test.ts',
	'src/__tests__/commands/virtualdevices/events.test.ts',
	'src/__tests__/commands/virtualdevices/update.test.ts',
	'src/__tests__/lib/commands/apps-util.test.ts',
	'src/__tests__/lib/commands/capabilities-util.test.ts',
	'src/__tests__/lib/commands/deviceprofiles-util.test.ts',
	'src/__tests__/lib/commands/deviceprofiles/view-util.test.ts',
	'src/__tests__/lib/commands/devices-util.test.ts',
	'src/__tests__/lib/commands/history-util.test.ts',
	'src/__tests__/lib/commands/installeddschema-util.test.ts',
	'src/__tests__/lib/commands/locations/rooms-util.test.ts',
	'src/__tests__/lib/commands/rules-util.test.ts',
	'src/__tests__/lib/commands/scenes-util.test.ts',
	'src/__tests__/lib/commands/virtualdevices-util.test.ts',
	'src/commands/apps.ts',
	'src/commands/apps/authorize.ts',
	'src/commands/apps/create.ts',
	'src/commands/apps/delete.ts',
	'src/commands/apps/oauth.ts',
	'src/commands/apps/oauth/generate.ts',
	'src/commands/apps/oauth/update.ts',
	'src/commands/apps/register.ts',
	'src/commands/apps/settings.ts',
	'src/commands/apps/settings/update.ts',
	'src/commands/apps/update.ts',
	'src/commands/capabilities.ts',
	'src/commands/capabilities/create.ts',
	'src/commands/capabilities/delete.ts',
	'src/commands/capabilities/namespaces.ts',
	'src/commands/capabilities/presentation.ts',
	'src/commands/capabilities/presentation/create.ts',
	'src/commands/capabilities/presentation/update.ts',
	'src/commands/capabilities/translations.ts',
	'src/commands/capabilities/translations/create.ts',
	'src/commands/capabilities/translations/update.ts',
	'src/commands/capabilities/translations/upsert.ts',
	'src/commands/capabilities/update.ts',
	'src/commands/config.ts',
	'src/commands/config/reset.ts',
	'src/commands/devicepreferences.ts',
	'src/commands/devicepreferences/create.ts',
	'src/commands/devicepreferences/translations.ts',
	'src/commands/devicepreferences/translations/create.ts',
	'src/commands/devicepreferences/translations/update.ts',
	'src/commands/devicepreferences/update.ts',
	'src/commands/deviceprofiles.ts',
	'src/commands/deviceprofiles/create.ts',
	'src/commands/deviceprofiles/delete.ts',
	'src/commands/deviceprofiles/device-config.ts',
	'src/commands/deviceprofiles/presentation.ts',
	'src/commands/deviceprofiles/publish.ts',
	'src/commands/deviceprofiles/translations.ts',
	'src/commands/deviceprofiles/translations/delete.ts',
	'src/commands/deviceprofiles/translations/upsert.ts',
	'src/commands/deviceprofiles/update.ts',
	'src/commands/deviceprofiles/view.ts',
	'src/commands/deviceprofiles/view/create.ts',
	'src/commands/deviceprofiles/view/update.ts',
	'src/commands/devices.ts',
	'src/commands/devices/capability-status.ts',
	'src/commands/devices/commands.ts',
	'src/commands/devices/component-status.ts',
	'src/commands/devices/delete.ts',
	'src/commands/devices/health.ts',
	'src/commands/devices/history.ts',
	'src/commands/devices/preferences.ts',
	'src/commands/devices/presentation.ts',
	'src/commands/devices/rename.ts',
	'src/commands/devices/status.ts',
	'src/commands/devices/update.ts',
	'src/commands/installedapps.ts',
	'src/commands/installedapps/delete.ts',
	'src/commands/installedapps/rename.ts',
	'src/commands/installedschema.ts',
	'src/commands/installedschema/delete.ts',
	'src/commands/locations.ts',
	'src/commands/locations/create.ts',
	'src/commands/locations/delete.ts',
	'src/commands/locations/history.ts',
	'src/commands/locations/rooms.ts',
	'src/commands/locations/rooms/create.ts',
	'src/commands/locations/rooms/delete.ts',
	'src/commands/locations/rooms/update.ts',
	'src/commands/locations/update.ts',
	'src/commands/logout.ts',
	'src/commands/organizations.ts',
	'src/commands/organizations/current.ts',
	'src/commands/presentation.ts',
	'src/commands/presentation/device-config.ts',
	'src/commands/presentation/device-config/create.ts',
	'src/commands/presentation/device-config/generate.ts',
	'src/commands/rules.ts',
	'src/commands/rules/create.ts',
	'src/commands/rules/delete.ts',
	'src/commands/rules/execute.ts',
	'src/commands/rules/update.ts',
	'src/commands/scenes.ts',
	'src/commands/scenes/execute.ts',
	'src/commands/schema.ts',
	'src/commands/schema/authorize.ts',
	'src/commands/schema/create.ts',
	'src/commands/schema/delete.ts',
	'src/commands/schema/regenerate.ts',
	'src/commands/schema/update.ts',
	'src/commands/virtualdevices.ts',
	'src/commands/virtualdevices/create-standard.ts',
	'src/commands/virtualdevices/create.ts',
	'src/commands/virtualdevices/delete.ts',
	'src/commands/virtualdevices/events.ts',
	'src/commands/virtualdevices/update.ts',
	'src/hooks/init/init-config.ts',
	'src/lib/aws-utils.ts',
	'src/lib/commands/apps-util.ts',
	'src/lib/commands/capabilities-util.ts',
	'src/lib/commands/devicepreferences-util.ts',
	'src/lib/commands/devicepreferences/translations-util.ts',
	'src/lib/commands/deviceprofiles-util.ts',
	'src/lib/commands/deviceprofiles/create-util.ts',
	'src/lib/commands/deviceprofiles/translations-util.ts',
	'src/lib/commands/deviceprofiles/view-util.ts',
	'src/lib/commands/devices-util.ts',
	'src/lib/commands/history-util.ts',
	'src/lib/commands/installedapps-util.ts',
	'src/lib/commands/installedschema-util.ts',
	'src/lib/commands/locations/rooms-util.ts',
	'src/lib/commands/rules-util.ts',
	'src/lib/commands/scenes-util.ts',
	'src/lib/commands/schema-util.ts',
	'src/lib/commands/virtualdevices-util.ts',
]

module.exports = shared
